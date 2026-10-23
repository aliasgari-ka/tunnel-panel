package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// The panel's address: --tls in the systemd unit is "" (plain HTTP), "self" or a
// comma-separated list of domains, each with its own Let's Encrypt certificate (renewed by
// autocert well before it expires). The installer asks for it; afterwards it is changed
// from Settings or with `tunnel-panel set-domain`, which rewrite the unit and restart.

var panelUnit = "/etc/systemd/system/tunnel-panel.service" // var: tests point it elsewhere

// panelTLS is the --tls value this process runs with.
var panelTLS string

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// normDomains checks and normalises "a.example.com, b.sslip.io".
func normDomains(v string) (string, error) {
	ds := splitDomains(v)
	if len(ds) == 0 {
		return "", fmt.Errorf("enter at least one domain")
	}
	if len(ds) > 5 {
		return "", fmt.Errorf("at most 5 domains")
	}
	for _, d := range ds {
		if !domainRe.MatchString(d) {
			return "", fmt.Errorf("%q is not a domain name", d)
		}
	}
	return strings.Join(ds, ","), nil
}

var unitTLSRe = regexp.MustCompile(`--tls ("[^"]*"|'[^']*'|\S*)`)

// setUnitDomains rewrites --tls (and --addr to :443) in the panel's unit file.
func setUnitDomains(domains string) error {
	b, err := os.ReadFile(panelUnit)
	if err != nil {
		return fmt.Errorf("read %s: %w", panelUnit, err)
	}
	unit := string(b)
	if !strings.Contains(unit, "ExecStart=") {
		return fmt.Errorf("%s has no ExecStart line", panelUnit)
	}
	if unitTLSRe.MatchString(unit) {
		unit = unitTLSRe.ReplaceAllString(unit, `--tls "`+domains+`"`)
	} else {
		unit = regexp.MustCompile(`(?m)^(ExecStart=.*)$`).ReplaceAllString(unit, `$1 --tls "`+domains+`"`)
	}
	unit = regexp.MustCompile(`--addr \S+`).ReplaceAllString(unit, "--addr 0.0.0.0:443")
	if err := os.WriteFile(panelUnit+".tmp", []byte(unit), 0o644); err != nil {
		return err
	}
	if err := os.Rename(panelUnit+".tmp", panelUnit); err != nil {
		return err
	}
	return exec.Command("systemctl", "daemon-reload").Run()
}

// dnsNote says where each domain points, so a domain that doesn't lead here is noticed
// before Let's Encrypt refuses it.
func dnsNote(domains string, own []string) string {
	var notes []string
	for _, d := range splitDomains(domains) {
		ips, err := net.LookupHost(d)
		if err != nil {
			notes = append(notes, d+": does not resolve yet")
			continue
		}
		here := false
		for _, ip := range ips {
			for _, o := range own {
				if o != "" && ip == o {
					here = true
				}
			}
		}
		if !here {
			notes = append(notes, fmt.Sprintf("%s points to %s, not to this server — a CDN proxy in front (e.g. Cloudflare's orange cloud) must pass port 80 through, or set the record to DNS-only", d, strings.Join(ips, ", ")))
		}
	}
	return strings.Join(notes, "; ")
}

// domain shows (GET) or sets (POST {Domains}) the panel's HTTPS domains; a change restarts
// the panel a few seconds after the answer, but never while a job runs.
func (s *Server2) domain(w http.ResponseWriter, r *http.Request) {
	set := s.app.settings()
	own := []string{set.LocalIPv4, set.LocalIPv6}
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]string{"tls": panelTLS})
		return
	}
	var in struct{ Domains string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	domains, err := normDomains(in.Domains)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if s.app.jobs.anyRunning() {
		httpErr(w, 409, "a job is running — change the domain when it has finished (the panel restarts)")
		return
	}
	if err := setUnitDomains(domains); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]string{"ok": "1", "tls": domains, "url": "https://" + splitDomains(domains)[0] + "/", "note": dnsNote(domains, own)})
	go func() {
		time.Sleep(3 * time.Second)
		_ = exec.Command("systemctl", "restart", "tunnel-panel").Run()
	}()
}

// setDomainCmd: tunnel-panel set-domain panel.example.com[,other.example.org]
func setDomainCmd(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: tunnel-panel set-domain panel.example.com[,other.example.org]")
	}
	domains, err := normDomains(args[0])
	if err != nil {
		return err
	}
	if err := setUnitDomains(domains); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "restart", "tunnel-panel").Run(); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	for _, d := range splitDomains(domains) {
		fmt.Printf("Panel: https://%s/  (the certificate is fetched on the first visit and renewed automatically)\n", d)
	}
	return nil
}
