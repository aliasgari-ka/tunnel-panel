package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// OptimizeResult is the per-server kernel-tuning report.
type OptimizeResult struct {
	Kernel     string   `json:"kernel"`
	Virt       string   `json:"virt"`
	RAMMB      int      `json:"ramMB"`
	CPUs       int      `json:"cpus"`
	CC         string   `json:"cc"`         // current congestion control
	AvailCC    string   `json:"availCc"`    // available controls
	BBR        bool     `json:"bbr"`        // bbr usable
	Qdisc      string   `json:"qdisc"`      // current default qdisc
	Notes      []string `json:"notes"`      // human notes about choices
	SysctlConf string   `json:"sysctlConf"` // the file we recommend
	Applied    bool     `json:"applied"`
	Output     string   `json:"output"` // apply output
	Manual     string   `json:"manual"` // paste-to-run command if auto failed / for manual use
	Reachable  bool     `json:"reachable"`
	Error      string   `json:"error,omitempty"`
}

const optzDetect = `
echo "KERNEL=$(uname -r)"
echo "VIRT=$(systemd-detect-virt 2>/dev/null || echo unknown)"
echo "RAMKB=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null)"
echo "CPUS=$(nproc 2>/dev/null || echo 1)"
echo "CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
echo "AVAILCC=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)"
echo "QDISC=$(sysctl -n net.core.default_qdisc 2>/dev/null)"
if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then echo "BBR=builtin";
elif modprobe -n tcp_bbr >/dev/null 2>&1; then echo "BBR=module";
else echo "BBR=no"; fi
echo "WRITABLE=$([ -w /etc/sysctl.d ] && echo yes || echo no)"
`

// Optimize detects a server and builds (and optionally applies) kernel tuning scaled to it.
func (a *App) Optimize(ctx context.Context, srv *Server, apply bool) OptimizeResult {
	var r OptimizeResult
	host, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		r.Error = "cannot reach server: " + err.Error()
		return r
	}
	r.Reachable = true
	out, _ := host.Run(ctx, optzDetect, nil)
	kv := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if i := strings.Index(l, "="); i > 0 {
			kv[strings.TrimSpace(l[:i])] = strings.TrimSpace(l[i+1:])
		}
	}
	r.Kernel, r.Virt, r.CC, r.AvailCC, r.Qdisc = kv["KERNEL"], kv["VIRT"], kv["CC"], kv["AVAILCC"], kv["QDISC"]
	r.CPUs, _ = strconv.Atoi(kv["CPUS"])
	if ramkb, _ := strconv.Atoi(kv["RAMKB"]); ramkb > 0 {
		r.RAMMB = ramkb / 1024
	}
	bbr := kv["BBR"]
	r.BBR = bbr == "builtin" || bbr == "module"

	r.SysctlConf, r.Notes = buildSysctl(r)
	r.Manual = manualOptz(r.SysctlConf, r.BBR)

	if apply {
		if kv["WRITABLE"] != "yes" {
			r.Notes = append(r.Notes, "/etc/sysctl.d is not writable as this user — run the manual command as root.")
		}
		applyScript := fmt.Sprintf(`set -e
cat >/etc/sysctl.d/99-tunnel-panel-optz.conf <<'SYSCTL'
%s
SYSCTL
%s
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-tunnel-panel-optz.conf
%s
mkdir -p /etc/security/limits.d
printf '* soft nofile 1048576\n* hard nofile 1048576\nroot soft nofile 1048576\nroot hard nofile 1048576\n' >/etc/security/limits.d/99-tunnel-panel.conf
echo APPLIED_OK
`, r.SysctlConf, bbrLoad(r.BBR), ipv6RAFix)
		o, err := host.Run(ctx, applyScript, nil)
		r.Output = strings.TrimSpace(o)
		r.Applied = err == nil && strings.Contains(o, "APPLIED_OK")
		if !r.Applied {
			r.Notes = append(r.Notes, "Automatic apply failed — run the manual command below as root.")
		} else {
			cur, _ := host.Run(ctx, "sysctl -n net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null", nil)
			r.Output += "\nnow: " + strings.ReplaceAll(strings.TrimSpace(cur), "\n", " / ")
		}
	}
	return r
}

func bbrLoad(bbr bool) string {
	if !bbr {
		return `echo "note: BBR not available on this kernel; keeping the current congestion control"`
	}
	return "modprobe tcp_bbr 2>/dev/null || true\necho tcp_bbr >/etc/modules-load.d/tunnel-panel-bbr.conf"
}

// buildSysctl scales buffers to RAM and only selects BBR/fq when available.
func buildSysctl(r OptimizeResult) (string, []string) {
	var notes []string
	cc := "cubic"
	if r.BBR {
		cc = "bbr"
		notes = append(notes, "BBR is available — selecting bbr + fq for better throughput on lossy links.")
	} else {
		notes = append(notes, "BBR not available on kernel "+r.Kernel+" — keeping cubic; consider a newer kernel.")
	}
	// buffer ceiling by RAM
	maxBuf := 16 * 1024 * 1024
	switch {
	case r.RAMMB >= 4096:
		maxBuf = 64 * 1024 * 1024
	case r.RAMMB >= 2048:
		maxBuf = 32 * 1024 * 1024
	case r.RAMMB > 0 && r.RAMMB < 1024:
		maxBuf = 8 * 1024 * 1024
		notes = append(notes, fmt.Sprintf("Low RAM (%d MB) — using conservative 8 MB socket buffers.", r.RAMMB))
	}
	backlog := 5000
	somax := 65535
	if r.RAMMB > 0 && r.RAMMB < 1024 {
		backlog, somax = 2500, 16384
	}
	wmemHi := maxBuf
	// ip_local_reserved_ports keeps the panel's own ports (panelPorts: 40000 + index*4 … and the
	// bench slot, the hot-standby probes 49000+, the forwarder paths 50000+) out of the
	// ephemeral range: an outgoing connection that got one of them made the tunnel or probe
	// there fail with "address already in use" (seen live)
	conf := fmt.Sprintf(`# Tunnel Panel — kernel tuning for a tunnel relay (%s, %d MB RAM, %d CPU, %s)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=%s
net.core.rmem_max=%d
net.core.wmem_max=%d
net.core.rmem_default=%d
net.core.wmem_default=%d
net.ipv4.tcp_rmem=4096 87380 %d
net.ipv4.tcp_wmem=4096 65536 %d
net.core.netdev_max_backlog=%d
net.core.somaxconn=%d
net.ipv4.tcp_max_syn_backlog=%d
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_keepalive_time=120
net.ipv4.ip_local_port_range=10000 65535
net.ipv4.ip_local_reserved_ports=40000-41023,49000-49255,50000-55000
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.ipv4.ip_forward=1
fs.file-max=1048576
`, r.Virt, r.RAMMB, r.CPUs, cc, cc, maxBuf, maxBuf, maxBuf/4, maxBuf/4, maxBuf, wmemHi, backlog, somax, backlog)
	return strings.TrimRight(conf, "\n"), notes
}

func manualOptz(conf string, bbr bool) string {
	return fmt.Sprintf(`sudo tee /etc/sysctl.d/99-tunnel-panel-optz.conf >/dev/null <<'SYSCTL'
%s
SYSCTL
%s
sudo sysctl --system
printf '* soft nofile 1048576\n* hard nofile 1048576\n' | sudo tee /etc/security/limits.d/99-tunnel-panel.conf >/dev/null`,
		conf, "sudo "+strings.ReplaceAll(bbrLoad(bbr), "\n", "\nsudo "))
}
