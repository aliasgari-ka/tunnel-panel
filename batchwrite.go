package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Writing a plan's files one WriteFile at a time costs one SSH session (or agent stream) per
// file: ~0.4 s each, so a switcher with 20 files took 8 s. writeBatch writes them in one
// script instead, and only the ones whose content differs from what the host already has.

const (
	batchMaxFile  = 512 << 10 // bigger files go one by one (raw, not base64 in a script)
	batchMaxTotal = 2 << 20   // the script, base64 included, stays well under any limit
	batchMark     = "TPW-"    // the script's own lines, read here and kept out of the job log
)

// batchFile is one file for writeBatch.
type batchFile struct {
	path string
	data []byte
	mode os.FileMode
}

// writeBatchScript is a bash fragment that writes files whose sha256 differs on the host (an
// equal one only gets its mode set) and prints "TPW-W <path>" for each one written. A write
// that fails prints "TPW-FAIL <path>" and exits 71; a host without base64 prints TPW-NOB64
// and exits 72 before touching anything. It falls through (no exit) when all went well.
func writeBatchScript(files []batchFile) string {
	var b strings.Builder
	b.WriteString("command -v base64 >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1 || { echo " + batchMark + "NOB64; exit 72; }\n")
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		p := shq(f.path)
		tmp := shq(f.path + ".tp-tmp")
		fmt.Fprintf(&b, "if [ -f %[1]s ] && [ \"$(sha256sum < %[1]s 2>/dev/null | cut -c1-64)\" = %[2]s ]; then chmod %[3]o %[1]s 2>/dev/null; else\n", p, hex.EncodeToString(sum[:]), f.mode)
		fmt.Fprintf(&b, "mkdir -p %s && base64 -d > %s <<'TP.EOF' && chmod %o %s && mv -f %s %s || { rm -f %s; echo %sFAIL %s; exit 71; }\n",
			shq(filepath.ToSlash(filepath.Dir(f.path))), tmp, f.mode, tmp, tmp, p, tmp, batchMark, p)
		enc := base64.StdEncoding.EncodeToString(f.data)
		for len(enc) > 76 {
			b.WriteString(enc[:76])
			b.WriteByte('\n')
			enc = enc[76:]
		}
		if enc != "" {
			b.WriteString(enc)
			b.WriteByte('\n')
		}
		b.WriteString("TP.EOF\n")
		fmt.Fprintf(&b, "echo %sW %s\nfi\n", batchMark, p)
	}
	return b.String()
}

// batchResult is what one batched run wrote.
type batchResult struct {
	total   int
	written []string // paths whose content changed
	fail    string   // the path a write failed on
	nob64   bool
}

// batchLog wraps a job logger: the writer's own lines are collected, the rest pass through.
func (r *batchResult) logf(next func(string)) func(string) {
	return func(l string) {
		s := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(s, batchMark+"W "):
			r.written = append(r.written, strings.Trim(strings.TrimPrefix(s, batchMark+"W "), "'"))
		case strings.HasPrefix(s, batchMark+"FAIL "):
			r.fail = strings.Trim(strings.TrimPrefix(s, batchMark+"FAIL "), "'")
		case s == batchMark+"NOB64":
			r.nob64 = true
		case s == batchMark+"OK":
			// the end of the writes: not a line for the job's log (it showed as "[IR] TPW-OK")
		default:
			if next != nil {
				next(l)
			}
		}
	}
}

// summary is the job's one line for the batch: "wrote 3 changed files of 20 (conf, targets, up-2.sh)".
func (r *batchResult) summary() string {
	if len(r.written) == 0 {
		return fmt.Sprintf("files up to date (%d, none changed)", r.total)
	}
	names := make([]string, 0, len(r.written))
	for _, p := range r.written {
		names = append(names, filepath.Base(filepath.FromSlash(p)))
	}
	sort.Strings(names)
	list := ""
	if len(names) <= 6 {
		list = " (" + strings.Join(names, ", ") + ")"
	}
	return fmt.Sprintf("wrote %d changed file(s) of %d%s", len(r.written), r.total, list)
}

// splitBatch puts the files that fit a batched script in batch (sorted by path, so the script
// is the same each time) and the rest in single.
func splitBatch(files map[string]FileSpec) (batch, single []batchFile) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	total := 0
	for _, p := range paths {
		f := batchFile{p, files[p].Content, files[p].Mode}
		if len(f.data) > batchMaxFile || total+len(f.data) > batchMaxTotal {
			single = append(single, f)
			continue
		}
		total += len(f.data)
		batch = append(batch, f)
	}
	return batch, single
}

// runWithFiles writes files on h and then runs script (which may be empty), in one round trip
// for all files that fit a batch. Files that don't fit, or a host without base64, are written
// one by one with WriteFile first. log gets script's output and one summary line for the
// files. A failed write returns an error naming the file; script's own failure returns its
// output and error as h.Run does (the files are written by then).
func runWithFiles(ctx context.Context, h Host, files map[string]FileSpec, script string, log func(string)) (string, error) {
	batch, single := splitBatch(files)
	if !canBatch(h) {
		single, batch = append(single, batch...), nil
	}
	one := func(fs []batchFile) error {
		for _, f := range fs {
			if err := h.WriteFile(f.path, f.data, f.mode); err != nil {
				return &fileWriteError{err}
			}
		}
		return nil
	}
	if err := one(single); err != nil {
		return "", err
	}
	if len(batch) == 0 {
		if len(single) > 0 && log != nil {
			log(fmt.Sprintf("wrote %d file(s)", len(single)))
		}
		if script == "" {
			return "", nil
		}
		return h.Run(ctx, script, log)
	}
	r := &batchResult{total: len(batch) + len(single)}
	// the writes first; script runs after them in the same shell, as its own top level
	// (an "exit 0" in it ends the run, as it did when it ran alone)
	out, err := h.Run(ctx, writeBatchScript(batch)+"echo "+batchMark+"OK\n"+script, r.logf(log))
	if r.nob64 {
		if err := one(batch); err != nil {
			return "", err
		}
		r.written = nil
		if log != nil {
			log(fmt.Sprintf("wrote %d file(s) one by one (no base64 on this host)", len(batch)+len(single)))
		}
		if script == "" {
			return "", nil
		}
		return h.Run(ctx, script, log)
	}
	if r.fail != "" {
		return out, &fileWriteError{withTail(fmt.Errorf("write %s: %w", r.fail, orErr(err)), stripBatch(out))}
	}
	if err != nil && !strings.Contains(out, batchMark+"OK") {
		// the connection broke before the writes ended (or the script never ran)
		return stripBatch(out), &fileWriteError{fmt.Errorf("writing %d files: %w", len(batch), orErr(err))}
	}
	r.written = append(r.written, pathsOf(single)...)
	if log != nil {
		log(r.summary())
	}
	return stripBatch(out), err
}

// batchHost is a host whose Run is a real shell, where a batched write script works (SSH,
// the agent, this machine). Any other Host gets its files one WriteFile at a time.
type batchHost interface{ batchWrites() bool }

func canBatch(h Host) bool {
	b, ok := h.(batchHost)
	return ok && b.batchWrites()
}

func (*SSHHost) batchWrites() bool  { return true }
func (AgentHost) batchWrites() bool { return true }
func (LocalHost) batchWrites() bool { return true }
func (l labeled) batchWrites() bool { return canBatch(l.Host) }

// fileWriteError is runWithFiles failing on the files, before its script ran.
type fileWriteError struct{ error }

func (e *fileWriteError) Unwrap() error { return e.error }

// quietFiles drops runWithFiles' summary line (for a single file not worth a line of its own).
func quietFiles(log func(string)) func(string) {
	return func(l string) {
		if !strings.HasPrefix(l, "files up to date (") && !strings.HasPrefix(l, "wrote ") {
			log(l)
		}
	}
}

func pathsOf(fs []batchFile) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.path)
	}
	return out
}

func orErr(err error) error {
	if err == nil {
		return fmt.Errorf("failed")
	}
	return err
}

// stripBatch takes the writer's marker lines out of a run's output.
func stripBatch(out string) string {
	if !strings.Contains(out, batchMark) {
		return out
	}
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), batchMark) {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}
