package main

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A hot-standby path that is down used to show one vague line ("running on the Iran
// server, but no answer comes through it", "heartbeat timeout"), while the real causes of
// past outages were each very different: another program's NAT rule eating the carrier
// (2026-11-11), the route cutting raw-TCP flows, a heartbeat setting, a core stuck after
// its sessions dropped (2026-11-12, nl). The cause finder looks once, when a path goes
// down, and names what it proved, with the side, the evidence and what to do:
//
//  1. the path's core on each server: installed, running, restarting, killed for memory,
//     and what it logged in this run (port taken, keys or licence refused, TLS, tun…);
//  2. the switcher's probe server on the foreign side and the path's check port on Iran;
//  3. the connection between the cores: who listens, who connects, connections open or
//     stuck in SYN-SENT, a TCP connect from each side to the other's port, a NAT rule that
//     isn't the panel's catching the port, the firewall;
//  4. L3 paths: the tunnel interface, packets sent by one side and received by the other,
//     the inner address;
//  5. ping between the servers, small and big (MTU);
//  6. the route cutting the connection again and again, Paqet's losses;
//  7. memory, CPU, OOM kills;
//  8. a panel job on the tunnel right before the drop.
//
// It costs two short read-only scripts per server, at most once every dcMinGap per path,
// two hunts at a time across the panel; the result is kept and shown until the path is up.

// DownCause is what the panel found about a path that is down.
type DownCause struct {
	Key      string   `json:"key"`    // method|family
	At       int64    `json:"at"`     // when it was found (panel clock)
	DownAt   int64    `json:"downAt"` // the switcher's "down since" it was found for
	Side     string   `json:"side"`   // iran | foreign | route | panel | ""
	Code     string   `json:"code"`
	Text     string   `json:"text"`
	TextFa   string   `json:"textFa"`
	Action   string   `json:"action,omitempty"`
	ActionFa string   `json:"actionFa,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
	Restart  bool     `json:"restart,omitempty"` // restarting the path's cores is the suggested fix
}

const (
	dcEvery   = 15 * time.Minute // a cause this old is looked for again while the path stays down
	dcMinGap  = 5 * time.Minute  // never more often than this per path
	dcRecent  = 15 * time.Minute // log lines this recent count as "now"
	dcCPUBusy = 90               // % of all cores busy (one-second sample) that counts as overloaded
	dcSlowMin = 20               // "queue full, dropping" lines in the recent log that prove a core too slow
)

// dcSem: at most two hunts at a time across the panel.
var dcSem = make(chan struct{}, 2)

// dcState is the finder's cache (under App.healthMu).
type dcState struct {
	cache map[string]*DownCause // "tunnel id|method|family"
	busy  map[string]bool
	tried map[string]time.Time
}

// ---- facts ----

type dcLine struct {
	At   int64
	Text string
}

type dcSock struct {
	Proto, State string
	LAddr        string
	LPort        int
	RAddr        string
	RPort        int
}

type dcReach struct{ Port, RC, MS int }

// dcSide is what one server's scripts printed.
type dcSide struct {
	Where, WhereFa, Server string // "Iran server", "سرور ایران", its name
	Err                    string // the server couldn't be reached
	NoUnit                 bool
	State, Sub             string
	Restarts               int
	Since                  int64
	Emulated               bool
	Panics24               int
	Journal                []dcLine
	Socks                  []dcSock
	PingSmall, PingBig     int // loss %, -1 = not measured
	Inner                  int // loss % to the peer's inner address, -1 = not measured
	Iface                  string
	Pkts                   [2][2]int64 // [sample][rx,tx], -1 = none
	Probe, Fwd             int         // listeners on the probe / check port, -1 = not checked
	MemAvail, MemTotal     int64       // kB
	Load                   float64
	NProc                  int
	CPU                    int // % of all cores busy over one second, -1 = not measured
	OOM, NAT, Raw, InDrop  []string
	UFW, InPolicy          string
	Reach                  []dcReach
	Peer                   string // the address this side talks to
	Now                    int64
}

func (s *dcSide) name() string {
	if s.Server == "" {
		return s.Where
	}
	return s.Where + " (" + s.Server + ")"
}

func (s *dcSide) nameFa() string {
	if s.Server == "" {
		return s.WhereFa
	}
	return s.WhereFa + " (" + s.Server + ")"
}

// dcFactsScript prints one server's facts about unit: its state, sockets and log, the
// ping to the peer, the tunnel interface, the probe/check port, memory, NAT and firewall.
// Everything is read-only.
func dcFactsScript(unit, peer string, probe, fwd int, iface, inner string) string {
	return fmt.Sprintf("u=%s; peer=%s; probe=%d; fwd=%d; ifc=%s; inner=%s\n", shq(unit), shq(peer), probe, fwd, shq(iface), shq(inner)) + `echo "TS $(date +%s)"
if ! systemctl cat "$u" >/dev/null 2>&1; then echo NOUNIT; else
systemctl show -p ActiveState -p SubState -p NRestarts "$u" 2>/dev/null | sed 's/^/P /'
t=$(systemctl show -p ActiveEnterTimestamp --value "$u" 2>/dev/null); [ -n "$t" ] && echo "SINCE $(date -d "$t" +%s 2>/dev/null)"
pid=$(systemctl show -p MainPID --value "$u" 2>/dev/null)
[ "${pid:-0}" != 0 ] && { tr '\0' ' ' </proc/$pid/cmdline; readlink /proc/$pid/exe; } 2>/dev/null | grep -qE 'qemu|box64' && echo EMU
cg=$(systemctl show -p ControlGroup --value "$u" 2>/dev/null)
pids=$( { cat /sys/fs/cgroup$cg/cgroup.procs /sys/fs/cgroup/systemd$cg/cgroup.procs; } 2>/dev/null | paste -sd'|')
if [ -n "$pids" ]; then
  ss -Htanp 2>/dev/null | grep -E "pid=($pids)," | awk '{print "ST",$1,$4,$5}' | head -60
  ss -Huanp 2>/dev/null | grep -E "pid=($pids)," | awk '{print "SU",$1,$4,$5}' | head -30
fi
journalctl -u "$u" -n 600 -o short-unix --no-pager 2>/dev/null | grep -av '^-- ' | sed -E 's/^([0-9]+)(\.[0-9]+)? [^ ]+ [^ :]+: /@\1 /' | grep -avE '^@[0-9]+ ([[:space:]]|goroutine |created by )|\.go:[0-9]+|\(0x[0-9a-f?]*' | tail -n 150 | sed 's/\x1b\[[0-9;]*m//g' | tr -cd '[:print:]\n' | cut -c1-260 | sed 's/^/J /'
echo "PANICS $(journalctl -u "$u" --since -24h -o cat --no-pager 2>/dev/null | grep -acE '^(panic: |fatal error: )')"
fi
loss() { ping "$@" 2>/dev/null | grep -oE '[0-9.]+% packet loss' | cut -d% -f1; }
if [ -n "$peer" ]; then
  case "$peer" in *:*) b=1352;; *) b=1372;; esac
  echo "PING small $(loss -c3 -W2 -i0.3 -q "$peer")"
  echo "PING big $(loss -c3 -W2 -i0.3 -q -s $b -M do "$peer")"
fi
if [ -n "$ifc" ]; then
  if [ -e /sys/class/net/$ifc ]; then
    ip -o link show dev "$ifc" 2>/dev/null | grep -q '[<,]UP[,>]' && st=up || st=down
    echo "IF $st $(cat /sys/class/net/$ifc/statistics/rx_packets) $(cat /sys/class/net/$ifc/statistics/tx_packets)"
  else echo "IF missing"; fi
fi
[ -n "$inner" ] && echo "INNER $(loss -c10 -W2 -i0.2 -q "$inner")"
[ "$probe" -gt 0 ] && echo "PROBE $(ss -Htln "sport = :$probe" 2>/dev/null | grep -c .)"
[ "$fwd" -gt 0 ] && echo "FWD $(ss -Htln "sport = :$fwd" 2>/dev/null | grep -c .)"
awk '/^MemTotal/{t=$2}/^MemAvailable/{a=$2}END{print "MEM",a+0,t+0}' /proc/meminfo
echo "LOAD $(cut -d' ' -f1 /proc/loadavg) $(nproc)"
c1=$(head -n1 /proc/stat); sleep 1; c2=$(head -n1 /proc/stat)
echo "$c1 $c2" | awk '$1=="cpu"&&$12=="cpu"{t=0;for(i=2;i<=9;i++)t-=$i;for(i=13;i<=20;i++)t+=$i;id=$16+$17-$5-$6;if(t>0)printf "CPU %.0f\n",100*(t-id)/t}'
journalctl -k --since -3h -o short-unix --no-pager 2>/dev/null | grep -ai 'killed process' | tail -n 3 | cut -c1-200 | sed 's/^/OOM /'
{ iptables -w -t nat -S; ip6tables -w -t nat -S; } 2>/dev/null | grep -E -- '-j (REDIRECT|DNAT|TPROXY)' | grep -vE -- '^-A TP|-j TP' | head -n 30 | sed 's/^/NAT /'
{ iptables -w -t mangle -S; } 2>/dev/null | grep -E -- '-j TPROXY' | head -n 10 | sed 's/^/NAT /'
{ iptables -w -t raw -S; ip6tables -w -t raw -S; } 2>/dev/null | grep -iE 'notrack' | head -n 30 | sed 's/^/RAW /'
ufw status 2>/dev/null | head -n 1 | sed 's/^/UFW /'
iptables -w -S INPUT 2>/dev/null | head -n 1 | sed 's/^/POL /'
iptables -w -S INPUT 2>/dev/null | grep -E -- '-j (DROP|REJECT)' | head -n 15 | sed 's/^/IND /'
true
`
}

// dcReachScript connects from this server to the peer's TCP ports (rc 0 = connected,
// 124 = timed out, else refused/unreachable) and samples the tunnel interface again.
func dcReachScript(peer string, ports []int, iface string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "peer=%s; ifc=%s\n", shq(peer), shq(iface))
	for _, p := range ports {
		fmt.Fprintf(&b, "s=$(date +%%s%%N); timeout 4 bash -c \"exec 3<>/dev/tcp/$peer/%d\" 2>/dev/null; rc=$?; echo \"R %d $rc $(( ($(date +%%s%%N)-s)/1000000 ))\"\n", p, p)
	}
	b.WriteString(`[ -n "$ifc" ] && [ -e /sys/class/net/$ifc ] && echo "IF2 $(cat /sys/class/net/$ifc/statistics/rx_packets) $(cat /sys/class/net/$ifc/statistics/tx_packets)"
true
`)
	return b.String()
}

// splitHostPort is net.SplitHostPort for ss's columns ("*:40212", "[::ffff:1.2.3.4]:5",
// "1.2.3.4%eth0:80").
func dcHostPort(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, 0
	}
	p, _ := strconv.Atoi(s[i+1:])
	h := strings.Trim(s[:i], "[]")
	if j := strings.Index(h, "%"); j >= 0 {
		h = h[:j]
	}
	h = strings.TrimPrefix(h, "::ffff:")
	return h, p
}

// dcParse fills s from a facts or reach script's output.
func dcParse(s *dcSide, out string) {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, "\r")
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l, f[0]))
		num := func(i int) int64 {
			if i >= len(f) {
				return -1
			}
			n, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				return -1
			}
			return int64(n)
		}
		switch f[0] {
		case "TS":
			s.Now = num(1)
		case "NOUNIT":
			s.NoUnit = true
		case "P":
			k, v, _ := strings.Cut(rest, "=")
			switch k {
			case "ActiveState":
				s.State = v
			case "SubState":
				s.Sub = v
			case "NRestarts":
				s.Restarts, _ = strconv.Atoi(v)
			}
		case "SINCE":
			s.Since = num(1)
		case "EMU":
			s.Emulated = true
		case "ST", "SU":
			if len(f) >= 4 {
				la, lp := dcHostPort(f[2])
				ra, rp := dcHostPort(f[3])
				pr := "tcp"
				if f[0] == "SU" {
					pr = "udp"
				}
				s.Socks = append(s.Socks, dcSock{Proto: pr, State: f[1], LAddr: la, LPort: lp, RAddr: ra, RPort: rp})
			}
		case "J":
			ln := dcLine{Text: rest}
			if strings.HasPrefix(rest, "@") {
				if at, t, ok := strings.Cut(rest[1:], " "); ok {
					if n, err := strconv.ParseInt(at, 10, 64); err == nil {
						ln = dcLine{At: n, Text: t}
					}
				}
			}
			s.Journal = append(s.Journal, ln)
		case "PANICS":
			s.Panics24 = int(num(1))
		case "PING":
			if len(f) >= 2 {
				v := -1
				if len(f) >= 3 {
					v = int(num(2))
				}
				if f[1] == "small" {
					s.PingSmall = v
				} else {
					s.PingBig = v
				}
			}
		case "INNER":
			s.Inner = int(num(1))
		case "IF":
			if len(f) >= 2 {
				s.Iface = f[1]
				if len(f) >= 4 {
					s.Pkts[0] = [2]int64{num(2), num(3)}
				}
			}
		case "IF2":
			s.Pkts[1] = [2]int64{num(1), num(2)}
		case "PROBE":
			s.Probe = int(num(1))
		case "FWD":
			s.Fwd = int(num(1))
		case "MEM":
			s.MemAvail, s.MemTotal = num(1), num(2)
		case "LOAD":
			if len(f) >= 3 {
				s.Load, _ = strconv.ParseFloat(f[1], 64)
				s.NProc, _ = strconv.Atoi(f[2])
			}
		case "CPU":
			s.CPU = int(num(1))
		case "OOM":
			s.OOM = append(s.OOM, rest)
		case "NAT":
			s.NAT = append(s.NAT, rest)
		case "RAW":
			s.Raw = append(s.Raw, rest)
		case "UFW":
			s.UFW = rest
		case "POL":
			s.InPolicy = rest
		case "IND":
			s.InDrop = append(s.InDrop, rest)
		case "R":
			if len(f) >= 4 {
				s.Reach = append(s.Reach, dcReach{Port: int(num(1)), RC: int(num(2)), MS: int(num(3))})
			}
		}
	}
}

func newDCSide(where, whereFa, server, peer string) *dcSide {
	return &dcSide{Where: where, WhereFa: whereFa, Server: server, Peer: peer, PingSmall: -1, PingBig: -1, Inner: -1, CPU: -1,
		Probe: -1, Fwd: -1, MemAvail: -1, MemTotal: -1, Pkts: [2][2]int64{{-1, -1}, {-1, -1}}}
}

// ---- log patterns ----

// dcPat is one thing a core's log line can say. Strong patterns prove a cause on their own
// (seen in the core's current run); weak ones only say what the core sees of the trouble.
type dcPat struct {
	Code    string
	Methods []string // nil = every method
	Re      *regexp.Regexp
	En, Fa  string
	Strong  bool
}

// dcPatterns, most specific first. Samples from the live cores are in downcause_test.go.
var dcPatterns = []dcPat{
	{Code: "port_in_use", Strong: true, Re: regexp.MustCompile(`(?i)address already in use|bind: address in use|EADDRINUSE`),
		En: "its port is already taken by another program (address already in use)", Fa: "پورتش را برنامه‌ی دیگری گرفته است (address already in use)"},
	{Code: "license", Strong: true, Re: regexp.MustCompile(`(?i)licen[cs]e\b.{0,30}\b(invalid|expired|not valid|does not exist|mismatch|denied|rejected|fail\w*)|invalid licen[cs]e`),
		En: "its licence was refused", Fa: "لایسنسش رد شده است"},
	{Code: "auth", Strong: true, Re: regexp.MustCompile(`(?i)(authori[sz]ation|authenticat\w*|auth)\s+(failed|failure|error|invalid|denied|rejected)|token\s+(in login\s+)?(is\s+)?(invalid|mismatch|wrong|doesn'?t match)|invalid (token|psk|key)|wrong (password|token|psk|key)|(psk|key) mismatch|unauthori[sz]ed|bad (psk|token|key)`),
		En: "the two servers' keys or tokens don't match (authentication refused)", Fa: "کلید یا توکن دو سرور با هم نمی‌خواند (احراز هویت رد شد)"},
	{Code: "tls", Strong: true, Re: regexp.MustCompile(`(?i)tls: |x509: |remote error: tls|tls handshake (error|fail\w*|timeout)|handshake (failed|failure|error)`),
		En: "the TLS handshake between the servers fails (often Iran's filter breaking TLS to this address)", Fa: "دست‌دهی TLS بین دو سرور شکست می‌خورد (اغلب فیلتر ایران TLS به این آدرس را خراب می‌کند)"},
	{Code: "tun", Strong: true, Re: regexp.MustCompile(`(?i)/dev/net/tun|(create|open|setup|allocate)\w* tun\w*.*(fail|error|denied|not permitted)|tun\w*: (no such device|operation not permitted|device or resource busy)|cannot (create|open) tun`),
		En: "it can't create its tun interface", Fa: "نمی‌تواند رابط tun خودش را بسازد"},
	{Code: "binary", Strong: true, Re: regexp.MustCompile(`(?i)exec format error|status=203/EXEC|failed to execute|failed at step EXEC`),
		En: "its program file is missing or can't run on this CPU", Fa: "فایل برنامه‌اش نیست یا روی این پردازنده اجرا نمی‌شود"},
	{Code: "oom", Strong: true, Re: regexp.MustCompile(`(?i)cannot allocate memory|out of memory|oom-kill`),
		En: "it ran out of memory", Fa: "حافظه‌اش تمام شد"},
	{Code: "fds", Strong: true, Re: regexp.MustCompile(`(?i)too many open files`),
		En: "it ran out of open files (too many open files)", Fa: "سقف فایل‌های باز پر شد (too many open files)"},
	{Code: "config", Strong: true, Re: regexp.MustCompile(`(?i)(failed to|cannot|can't) (parse|load|read) (the )?config|invalid config|unknown (field|option|key) in|json: cannot unmarshal|toml: |yaml: line`),
		En: "its config file is rejected", Fa: "فایل تنظیماتش پذیرفته نمی‌شود"},
	{Code: "panic", Strong: true, Re: regexp.MustCompile(`^panic: |^fatal error: |SIGSEGV|segmentation (fault|violation)`),
		En: "the core crashed", Fa: "هسته از کار افتاد (crash)"},
	{Code: "paqet_loss", Methods: []string{"paqet"}, Re: hsPaqetLossRe,
		En: "the route drops most of its raw TCP frames", Fa: "مسیر بیشتر بسته‌های TCP خامش را دور می‌ریزد"},
	{Code: "heartbeat", Re: regexp.MustCompile(`(?i)heartbeat timeout`),
		En: "the cores on the two servers stopped hearing each other (heartbeat timeout)", Fa: "هسته‌های دو سرور دیگر صدای هم را نمی‌شنوند (heartbeat timeout)"},
	{Code: "dial_timeout", Re: regexp.MustCompile(`(?i)i/o timeout|dial \w+ [^ ]+: (connect: )?(connection )?timed out|connection timed out|context deadline exceeded`),
		En: "its connections to the other server time out", Fa: "اتصال‌هایش به سرور دیگر تایم‌اوت می‌شود"},
	{Code: "refused", Re: regexp.MustCompile(`(?i)connection refused`),
		En: "the other server refuses its connections", Fa: "سرور دیگر اتصال‌هایش را رد می‌کند"},
	{Code: "unreachable", Re: regexp.MustCompile(`(?i)no route to host|network is unreachable|host is unreachable`),
		En: "the other server is unreachable from it", Fa: "سرور دیگر از آن در دسترس نیست"},
	{Code: "reset", Re: regexp.MustCompile(`(?i)connection reset|broken pipe|unexpected EOF|session down|\bdisconnected\b|transport failed|lost connection|connection (closed|lost)`),
		En: "its connection to the other server drops", Fa: "اتصالش به سرور دیگر قطع می‌شود"},
}

// dcNoise: lines that look like errors but say nothing about an outage.
var dcNoise = regexp.MustCompile(`(?i)congestion control .* not available|file already closed|use of closed network connection|^mem: |Consumed [0-9.]+s CPU`)

// dcMatch is the first pattern line matches for method mid.
func dcMatch(mid, line string) *dcPat {
	if dcNoise.MatchString(line) {
		return nil
	}
	l := dcStripTime(line)
	for i := range dcPatterns {
		p := &dcPatterns[i]
		if len(p.Methods) > 0 && !inList(p.Methods, mid) {
			continue
		}
		if p.Re.MatchString(l) {
			return p
		}
	}
	return nil
}

var dcTimeRe = regexp.MustCompile(`^(\d{4}[/-]\d\d[/-]\d\d[ T]\d\d:\d\d:\d\d(\.\d+)?\S*\s+|\d\d-\w{3} \d\d:\d\d:\d\d\s+)`)

// dcStripTime drops the core's own time stamp in front of a line.
func dcStripTime(l string) string { return dcTimeRe.ReplaceAllString(strings.TrimSpace(l), "") }

func inList(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---- classification ----

// dcInput is everything the classifier looks at (no I/O: tests feed it real samples).
type dcInput struct {
	Method, Family, Title string
	L3, IfaceKnown        bool // L3 path; the interface name is the panel's tp<idx>
	Proto                 string
	ProbePort, FwdPort    int
	Internal              [2]int // Iran's internal forwarder ports of this path [lo, hi]
	DownAt                int64
	Now                   time.Time
	IR, KH                *dcSide
	Job                   *Job // the tunnel's latest panel job (nil = none)
	// UpVia: this tunnel's paths of the same family that carry their packets as a bare IP
	// protocol (GRE, ESP) and work right now — proof the two servers do reach each other
	UpVia []string
	// UpOther: a path of the same family that is not GRE/ESP works now — TCP or UDP does
	// pass this route, so it isn't GRE/ESP-only
	UpOther bool
}

// dcMask hides the last two parts of an IPv4 address and most of an IPv6 one.
func dcMask(ip string) string {
	if p := strings.Split(ip, "."); len(p) == 4 {
		return p[0] + "." + p[1] + ".x.x"
	}
	if i := strings.Index(ip, ":"); i >= 0 {
		return ip[:i] + ":…"
	}
	return ip
}

// dcEv cleans a log line for the page: addresses and secrets out, short.
func dcEv(side *dcSide, l dcLine) string {
	t := hsRedact(dcStripTime(l.Text))
	if len(t) > 200 {
		t = t[:200] + "…"
	}
	when := ""
	if l.At > 0 {
		when = time.Unix(l.At, 0).UTC().Format("15:04:05") + " UTC "
	}
	return side.Where + " log, " + when + t
}

type dcResult struct {
	side, code, en, fa, act, actFa string
	restart                        bool
	ev                             []string
}

func (r *dcResult) cause(key string, in *dcInput) *DownCause {
	return &DownCause{Key: key, At: in.Now.Unix(), DownAt: in.DownAt, Side: r.side, Code: r.code, Text: r.en, TextFa: r.fa,
		Action: r.act, ActionFa: r.actFa, Evidence: r.ev, Restart: r.restart}
}

const (
	actRestartEn = "restart this path (⋯ → Restart path); the panel also restarts a path by itself after 30 min down"
	actRestartFa = "این مسیر را ری‌استارت کنید (⋯ ← ری‌استارت مسیر)؛ پنل هم بعد از ۳۰ دقیقه قطعی خودش ری‌استارتش می‌کند"
	actRouteEn   = "the route blocks this method now — the switcher keeps the users on other paths; try another carrier or method on this route"
	actRouteFa   = "مسیر الان این روش را می‌بندد — سوییچر کاربران را روی مسیرهای دیگر نگه می‌دارد؛ کریر یا روش دیگری را روی این مسیر امتحان کنید"
)

// dcClassify names the first proven cause, in the order the header lists.
func dcClassify(in *dcInput) *dcResult {
	core, coreFa := in.Title+" core", "هسته‌ی "+in.Title
	sides := []*dcSide{in.IR, in.KH}
	now := in.Now.Unix()
	var extra []string // context that is no cause on its own (restarts, crashes, emulation)
	for _, s := range sides {
		if s.Restarts > 0 {
			extra = append(extra, fmt.Sprintf("%s: the core restarted %d times since the server booted", s.Where, s.Restarts))
		}
		if s.Panics24 > 0 {
			last := ""
			for i := len(s.Journal) - 1; i >= 0; i-- {
				if strings.HasPrefix(s.Journal[i].Text, "panic: ") || strings.HasPrefix(s.Journal[i].Text, "fatal error: ") {
					last = " — last: " + dcEv(s, s.Journal[i])
					break
				}
			}
			extra = append(extra, fmt.Sprintf("%s: the core crashed %d times in 24 h%s", s.Where, s.Panics24, last))
		}
		if s.Emulated {
			extra = append(extra, s.Where+": the core is an x86 build running under emulation (qemu/box64) on this ARM server — slower, and crashes the emulator causes are possible")
		}
	}
	res := func(side, code, en, fa, act, actFa string, restart bool, ev ...string) *dcResult {
		return &dcResult{side: side, code: code, en: en, fa: fa, act: act, actFa: actFa, restart: restart, ev: append(ev, extra...)}
	}
	sideID := func(s *dcSide) string {
		if s == in.IR {
			return "iran"
		}
		return "foreign"
	}
	other := func(s *dcSide) *dcSide {
		if s == in.IR {
			return in.KH
		}
		return in.IR
	}

	// 0. a server the panel can't read
	for _, s := range sides {
		if s.Err != "" {
			return res(sideID(s), "ssh",
				s.name()+": the panel can't reach it over SSH, so nothing on it could be checked ("+hsRedact(s.Err)+")",
				s.nameFa()+": پنل با SSH به آن نمی‌رسد، پس روی آن چیزی بررسی نشد ("+hsRedact(s.Err)+")",
				"check that server is on and its SSH answers", "روشن بودن آن سرور و جواب دادن SSH آن را بررسی کنید", false)
		}
	}

	// keyLine: the most telling log line of a side since `from` (strong patterns first)
	keyLine := func(s *dcSide, from int64) (*dcPat, dcLine) {
		var weak *dcPat
		var wl dcLine
		for i := len(s.Journal) - 1; i >= 0; i-- {
			l := s.Journal[i]
			if l.At > 0 && l.At < from {
				break
			}
			if p := dcMatch(in.Method, l.Text); p != nil {
				if p.Strong {
					return p, l
				}
				if weak == nil {
					weak, wl = p, l
				}
			}
		}
		return weak, wl
	}

	// 1. the path's core on each server
	for _, s := range sides {
		switch {
		case s.NoUnit:
			return res(sideID(s), "no_unit",
				s.name()+": this path's "+core+" isn't installed — the path was never set up there",
				s.nameFa()+": "+coreFa+"ِ این مسیر نصب نیست — مسیر آنجا راه‌اندازی نشده",
				"re-apply the tunnel, or remove this path", "تانل را دوباره اعمال کنید، یا این مسیر را حذف کنید", false)
		case s.State == "" || s.State == "active" || s.State == "reloading":
		default:
			p, l := keyLine(s, now-3*3600)
			for _, o := range s.OOM {
				if strings.Contains(strings.ToLower(o), "killed process") {
					return res(sideID(s), "oom", s.name()+": the "+core+" was killed for lack of memory (OOM)",
						s.nameFa()+": "+coreFa+" به‌خاطر کمبود حافظه کشته شد (OOM)",
						"free memory on that server, then restart this path", "روی آن سرور حافظه آزاد کنید، بعد این مسیر را ری‌استارت کنید", true, s.Where+" kernel: "+hsRedact(o))
				}
			}
			st, stFa := "has stopped ("+s.State+")", "متوقف شده ("+s.State+")"
			if s.State == "activating" || s.Sub == "auto-restart" {
				st, stFa = fmt.Sprintf("keeps crashing and restarting (%d restarts)", s.Restarts), fmt.Sprintf("مدام از کار می‌افتد و دوباره راه می‌افتد (%d بار)", s.Restarts)
			}
			en, fa := s.name()+": the "+core+" "+st, s.nameFa()+": "+coreFa+" "+stFa
			var ev []string
			if p != nil {
				en += " — " + p.En
				fa += " — " + p.Fa
				ev = append(ev, dcEv(s, l))
			}
			return res(sideID(s), "core_down", en, fa, actRestartEn, actRestartFa, true, ev...)
		}
	}
	// a route that passes only bare IP protocols (GRE 47, ESP 50): a GRE/ESP path of this
	// tunnel works, yet ping is lost and no TCP connect between the servers gets through.
	// Seen on the England and outbound OVH routes (2026-10-31, tcpdump on both ends: TCP,
	// UDP and ICMP from abroad never reach the Iran server). A TCP/UDP method can't work
	// there at all — no restart or carrier changes it — so it is named for what it is, not
	// as a fault, and the panel stops restarting it (hskick.go).
	if r := dcProtoFilter(in, core, coreFa, extra); r != nil {
		return r
	}
	// an error that proves the cause on its own, logged in the core's current run
	for _, s := range sides {
		from := s.Since
		if from == 0 {
			from = now - int64(dcRecent/time.Second)
		}
		if p, l := keyLine(s, from); p != nil && p.Strong {
			act, actFa, rs := actRestartEn, actRestartFa, true
			switch p.Code {
			case "auth", "license", "config":
				act, actFa, rs = "re-apply the tunnel so both servers get the same settings", "تانل را دوباره اعمال کنید تا هر دو سرور تنظیمات یکسان بگیرند", false
			case "tls":
				act, actFa, rs = actRouteEn, actRouteFa, false
			case "port_in_use":
				act, actFa = "free the port on "+s.Where+" (or let the panel move it: re-apply), then restart this path", "پورت را روی "+s.WhereFa+" آزاد کنید (یا با اعمال دوباره بگذارید پنل جابه‌جایش کند)، بعد مسیر را ری‌استارت کنید"
			}
			return res(sideID(s), p.Code, s.name()+": the "+core+" reports that "+p.En, s.nameFa()+": "+coreFa+" می‌گوید "+p.Fa, act, actFa, rs, dcEv(s, l))
		}
	}

	// 2. the switcher's probe server (foreign) and the path's check port (Iran)
	if in.KH.Probe == 0 {
		return res("foreign", "probe_down",
			fmt.Sprintf("%s: the switcher's probe server isn't listening on port %d — every path's check fails because of it, not the path", in.KH.name(), in.ProbePort),
			fmt.Sprintf("%s: سرور پروب سوییچر روی پورت %d گوش نمی‌دهد — بررسی همه‌ی مسیرها به همین دلیل رد می‌شود، نه به خاطر خود مسیر", in.KH.nameFa(), in.ProbePort),
			"re-apply the tunnel (it reinstalls the probe server)", "تانل را دوباره اعمال کنید (سرور پروب را دوباره نصب می‌کند)", false)
	}
	if in.IR.Fwd == 0 {
		return res("iran", "fwd_down",
			fmt.Sprintf("%s: the path doesn't listen on its check port %d — the %s runs without its port forwards", in.IR.name(), in.FwdPort, core),
			fmt.Sprintf("%s: مسیر روی پورت بررسی‌اش (%d) گوش نمی‌دهد — %s بدون فورواردهایش اجرا می‌شود", in.IR.nameFa(), in.FwdPort, coreFa),
			actRestartEn, actRestartFa, true)
	}

	// 3. the connection between the cores
	isLocal := func(a string) bool {
		return strings.HasPrefix(a, "127.") || a == "::1" || a == "localhost"
	}
	carrier := func(s *dcSide) []int { // the TCP ports this side's core listens on for the other server
		seen := map[int]bool{}
		var ps []int
		for _, k := range s.Socks {
			if k.Proto != "tcp" || k.State != "LISTEN" || isLocal(k.LAddr) || seen[k.LPort] {
				continue
			}
			if s == in.IR && k.LPort >= in.Internal[0] && k.LPort <= in.Internal[1] {
				continue // the users' forwards and the check port
			}
			if k.LPort == in.ProbePort {
				continue
			}
			seen[k.LPort] = true
			ps = append(ps, k.LPort)
		}
		sort.Ints(ps)
		return ps
	}
	// conns: this side's sockets to the peer on one of ports, by state
	conns := func(s *dcSide, ports []int, out bool) map[string]int {
		n := map[string]int{}
		for _, k := range s.Socks {
			if k.Proto != "tcp" || k.State == "LISTEN" || isLocal(k.RAddr) {
				continue
			}
			p := k.LPort
			if out {
				p = k.RPort
			}
			for _, x := range ports {
				if x == p {
					n[k.State]++
				}
			}
		}
		return n
	}
	var lis, cli *dcSide
	var ports []int
	if p := carrier(in.IR); len(p) > 0 {
		lis, cli, ports = in.IR, in.KH, p
	} else if p := carrier(in.KH); len(p) > 0 {
		lis, cli, ports = in.KH, in.IR, p
	}
	// a NAT rule that isn't the panel's, matching the carrier's port, takes the packets
	// before the core sees them (2026-11-11: the IG agent's REDIRECT of tcp 80/443)
	if lis != nil {
		for _, s := range sides {
			for _, r := range s.NAT {
				for _, p := range ports {
					if dcRuleHits(r, "tcp", p) && !dcExempt(s.Raw, p) {
						return res(sideID(s), "nat",
							fmt.Sprintf("%s: a NAT rule that isn't the panel's catches TCP port %d, which the %s uses — its packets go to another program instead of the other server (%s)", s.name(), p, core, dcRuleShort(r)),
							fmt.Sprintf("%s: یک قانون NAT که مال پنل نیست پورت TCP %d را می‌گیرد که %s از آن استفاده می‌کند — بسته‌هایش به جای سرور دیگر به برنامه‌ی دیگری می‌رود (%s)", s.nameFa(), p, coreFa, dcRuleShort(r)),
							"exempt this port from that rule (or stop the program that added it), then restart this path",
							"این پورت را از آن قانون مستثنا کنید (یا برنامه‌ای که اضافه‌اش کرده را متوقف کنید)، بعد مسیر را ری‌استارت کنید", true,
							s.Where+" firewall: "+hsRedact(r))
					}
				}
			}
		}
	}
	if lis != nil {
		pl := ports[0]
		est := conns(cli, ports, true)
		lisEst := conns(lis, ports, false)
		var reach *dcReach
		for i := range cli.Reach {
			if inInts(ports, cli.Reach[i].Port) {
				reach = &cli.Reach[i]
				pl = reach.Port
				break
			}
		}
		addr := dcMask(cli.Peer) // the address the client side connects to
		target := fmt.Sprintf("%s %s:%d", lis.Where, addr, pl)
		targetFa := fmt.Sprintf("%s %s:%d", lis.WhereFa, addr, pl)
		var ev []string
		ev = append(ev, fmt.Sprintf("%s: the %s listens on TCP %s", lis.Where, core, joinInts(ports)))
		ev = append(ev, fmt.Sprintf("%s: the %s's connections to it: %s", cli.Where, core, fmtStates(est)))
		if reach != nil {
			ev = append(ev, fmt.Sprintf("test: TCP connect from %s to %s: %s", cli.Where, target, reachText(reach)))
		}
		if cli.PingSmall >= 0 {
			ev = append(ev, fmt.Sprintf("test: ping from %s to %s: %d%% lost", cli.Where, lis.Where, cli.PingSmall))
		}
		ev = append(ev, dcLastLines(lis, in.Method, 2)...)
		ev = append(ev, dcLastLines(cli, in.Method, 2)...)
		fw, fwFa := dcFirewall(lis, ports)
		switch {
		case est["ESTAB"] == 0 && (est["SYN-SENT"] > 0 || reach != nil && reach.RC == 124):
			why, whyFa := "the route or Iran's filter drops them", "مسیر یا فیلتر ایران دورشان می‌ریزد"
			if fw != "" {
				why, whyFa = fw+", or the route drops them", fwFa+"، یا مسیر دورشان می‌ریزد"
			}
			return res("route", "blocked",
				fmt.Sprintf("%s: the %s can't reach %s over TCP — the connection times out; %s is listening, so %s", cli.name(), core, target, lis.Where, why),
				fmt.Sprintf("%s: %s به %s روی TCP نمی‌رسد — اتصال تایم‌اوت می‌شود؛ %s گوش می‌دهد، پس %s", cli.nameFa(), coreFa, targetFa, lis.WhereFa, whyFa),
				actRouteEn, actRouteFa, false, ev...)
		case est["ESTAB"] == 0 && reach != nil && reach.RC != 0:
			return res("route", "refused",
				fmt.Sprintf("%s: the %s's connections to %s are refused although it listens there — a firewall on the way rejects them", cli.name(), core, target),
				fmt.Sprintf("%s: اتصال‌های %s به %s رد می‌شود با اینکه آنجا گوش می‌دهد — یک فایروال در مسیر ردشان می‌کند", cli.nameFa(), coreFa, targetFa),
				actRouteEn, actRouteFa, false, ev...)
		case est["ESTAB"] == 0 && reach != nil:
			return res(sideID(cli), "stuck",
				fmt.Sprintf("%s: the %s is running but has no connection to %s and isn't reconnecting — that port answers (TCP connect in %d ms), so the route is fine; the core is stuck", cli.name(), core, target, reach.MS),
				fmt.Sprintf("%s: %s در حال اجراست ولی هیچ اتصالی به %s ندارد و دوباره وصل نمی‌شود — آن پورت جواب می‌دهد (اتصال TCP در %d میلی‌ثانیه)، پس مسیر سالم است؛ هسته گیر کرده", cli.nameFa(), coreFa, targetFa, reach.MS),
				actRestartEn, actRestartFa, true, ev...)
		case est["ESTAB"] > 0 && lisEst["ESTAB"] == 0:
			return res("route", "hijacked",
				fmt.Sprintf("%s: the %s's connections to %s look open on its side, but %s sees none of them — something on the way (a transparent proxy or NAT) takes them", cli.name(), core, target, lis.Where),
				fmt.Sprintf("%s: اتصال‌های %s به %s سمت خودش باز است، ولی %s هیچ‌کدام را نمی‌بیند — چیزی در مسیر (پراکسی شفاف یا NAT) آن‌ها را می‌گیرد", cli.nameFa(), coreFa, targetFa, lis.WhereFa),
				actRouteEn, actRouteFa, false, ev...)
		}
	}

	// 4. L3 paths: the interface, packets sent and received, the inner address
	var l3ev []string
	if in.L3 {
		if in.IfaceKnown {
			for _, s := range sides {
				if s.Iface == "missing" || s.Iface == "down" {
					return res(sideID(s), "iface",
						fmt.Sprintf("%s: the tunnel interface is %s — the %s didn't bring it up", s.name(), s.Iface, core),
						fmt.Sprintf("%s: رابط تانل %s است — %s آن را بالا نیاورده", s.nameFa(), map[string]string{"missing": "وجود ندارد", "down": "خاموش"}[s.Iface], coreFa),
						actRestartEn, actRestartFa, true)
				}
			}
		}
		d := func(s *dcSide, i int) int64 {
			if s.Pkts[0][i] < 0 || s.Pkts[1][i] < 0 {
				return -1
			}
			return s.Pkts[1][i] - s.Pkts[0][i]
		}
		ev := []string{fmt.Sprintf("%s: interface sent %s, received %s packets during the test", in.IR.Where, pk(d(in.IR, 1)), pk(d(in.IR, 0))),
			fmt.Sprintf("%s: interface sent %s, received %s packets during the test", in.KH.Where, pk(d(in.KH, 1)), pk(d(in.KH, 0)))}
		if in.IR.Inner >= 0 {
			ev = append(ev, fmt.Sprintf("test: ping from Iran to the foreign side's tunnel address: %d%% lost", in.IR.Inner))
		}
		l3ev = ev
		switch {
		case d(in.IR, 1) > 0 && d(in.KH, 0) == 0:
			return res("route", "l3_drop_out",
				fmt.Sprintf("the route drops this tunnel's %s packets from Iran to the foreign server: %s sent %d, %s received none", in.Proto, in.IR.name(), d(in.IR, 1), in.KH.name()),
				fmt.Sprintf("مسیر بسته‌های %s این تانل را از ایران به خارج دور می‌ریزد: %s %d بسته فرستاد، %s هیچ‌کدام را نگرفت", in.Proto, in.IR.nameFa(), d(in.IR, 1), in.KH.nameFa()),
				actRouteEn, actRouteFa, false, ev...)
		case d(in.KH, 1) > 0 && d(in.IR, 0) == 0:
			return res("route", "l3_drop_in",
				fmt.Sprintf("the route drops this tunnel's %s packets from the foreign server to Iran: %s sent %d, %s received none", in.Proto, in.KH.name(), d(in.KH, 1), in.IR.name()),
				fmt.Sprintf("مسیر بسته‌های %s این تانل را از خارج به ایران دور می‌ریزد: %s %d بسته فرستاد، %s هیچ‌کدام را نگرفت", in.Proto, in.KH.nameFa(), d(in.KH, 1), in.IR.nameFa()),
				actRouteEn, actRouteFa, false, ev...)
		case in.IR.Inner == 100 && in.IR.PingSmall >= 0 && in.IR.PingSmall < 100:
			return res("route", "l3_inner",
				fmt.Sprintf("the servers ping each other, but the foreign side's tunnel address doesn't answer through the tunnel — this tunnel's %s packets don't get through", in.Proto),
				fmt.Sprintf("دو سرور همدیگر را پینگ می‌کنند، ولی آدرس تانلِ سمت خارج از داخل تانل جواب نمی‌دهد — بسته‌های %s این تانل رد نمی‌شود", in.Proto),
				actRouteEn, actRouteFa, false, ev...)
		}
	}

	// 5. ping between the servers, small and big
	for _, s := range sides {
		tcpDead := false
		for _, r := range s.Reach {
			if r.RC == 124 {
				tcpDead = true
			}
		}
		if s.PingSmall == 100 && (tcpDead || len(s.Reach) == 0 && other(s).PingSmall == 100) {
			return res("route", "no_route",
				fmt.Sprintf("the two servers can't reach each other over %s at all right now (ping from %s: all lost%s)", famName(in.Family), s.Where, map[bool]string{true: ", TCP connects time out", false: ""}[tcpDead]),
				fmt.Sprintf("دو سرور الان روی %s اصلاً به هم نمی‌رسند (پینگ از %s: همه گم شد%s)", famName(in.Family), s.WhereFa, map[bool]string{true: "، اتصال TCP تایم‌اوت می‌شود", false: ""}[tcpDead]),
				"wait for the route to come back, or use the other address family", "صبر کنید مسیر برگردد، یا از خانواده‌ی آدرس دیگر استفاده کنید", false)
		}
	}
	for _, s := range sides {
		if s.PingSmall >= 0 && s.PingSmall < 50 && s.PingBig == 100 {
			return res("route", "mtu",
				fmt.Sprintf("big packets (1400 bytes) are dropped between the servers while small ones pass (ping from %s: %d%% small, 100%% big lost) — this path's MTU is too high for the route", s.Where, s.PingSmall),
				fmt.Sprintf("بسته‌های بزرگ (۱۴۰۰ بایت) بین دو سرور دور ریخته می‌شود ولی کوچک‌ها رد می‌شوند (پینگ از %s: کوچک %d%%، بزرگ ۱۰۰%% گم) — MTU این مسیر برای این مسیر شبکه زیاد است", s.WhereFa, s.PingSmall),
				"lower the MTU in this method's options (e.g. 1280)", "MTU را در تنظیمات این روش کم کنید (مثلاً ۱۲۸۰)", false)
		}
	}

	// most (not all) of an L3 tunnel's packets lost on the way: the pings through the
	// tunnel fail while the cores run and the servers still reach each other
	if in.L3 && in.IR.Inner >= 50 {
		return res("route", "l3_loss",
			fmt.Sprintf("the route loses most of this tunnel's %s packets: %d%% of the pings through the tunnel to the foreign side's tunnel address were lost", in.Proto, in.IR.Inner),
			fmt.Sprintf("مسیر بیشتر بسته‌های %s این تانل را گم می‌کند: %d%% پینگ‌ها از داخل تانل به آدرس تانلِ سمت خارج گم شد", in.Proto, in.IR.Inner),
			actRouteEn, actRouteFa, false, l3ev...)
	}

	// 6. the route cutting the connection again and again; Paqet's losses
	for _, s := range sides {
		mins := map[int64]bool{}
		var last dcLine
		for _, l := range s.Journal {
			if l.At < now-int64(dcRecent/time.Second) {
				continue
			}
			if p := dcMatch(in.Method, l.Text); p != nil {
				if p.Code == "paqet_loss" {
					m := hsPaqetLossRe.FindStringSubmatch(dcStripTime(l.Text))
					return res("route", "paqet_loss",
						"the route drops most of this path's raw TCP frames ("+strings.TrimSpace(m[1])+") — some flows are cut a few seconds in",
						"مسیر بیشتر بسته‌های TCP خام این مسیر را دور می‌ریزد ("+strings.TrimSpace(m[1])+") — بعضی جریان‌ها چند ثانیه بعد قطع می‌شوند",
						actRestartEn+" (a new flow may pass)", actRestartFa+" (جریان تازه ممکن است رد شود)", true, append([]string{dcEv(s, l)}, extra...)...)
				}
				if p.Code == "reset" || p.Code == "heartbeat" {
					mins[l.At/60] = true
					last = l
				}
			}
		}
		if len(mins) >= 3 {
			return res("route", "flaps",
				fmt.Sprintf("the connection between the servers keeps dropping: %d drops in the last 15 min in %s's log, each time the core reconnects — the route cuts long-lived connections", len(mins), s.Where),
				fmt.Sprintf("اتصال بین دو سرور مدام قطع می‌شود: %d قطعی در ۱۵ دقیقه‌ی اخیر در لاگ %s، و هر بار هسته دوباره وصل می‌شود — مسیر اتصال‌های طولانی را قطع می‌کند", len(mins), s.WhereFa),
				actRouteEn, actRouteFa, false, dcEv(s, last))
		}
	}

	// 7. memory, CPU, OOM kills
	for _, s := range sides {
		if s.MemTotal > 0 && s.MemAvail >= 0 && s.MemAvail*100 < s.MemTotal*5 {
			return res(sideID(s), "memory",
				fmt.Sprintf("%s: memory is almost full (%d MB free of %d MB) — the cores can't keep up", s.name(), s.MemAvail/1024, s.MemTotal/1024),
				fmt.Sprintf("%s: حافظه تقریباً پر است (%d مگابایت آزاد از %d) — هسته‌ها از پسش برنمی‌آیند", s.nameFa(), s.MemAvail/1024, s.MemTotal/1024),
				"free memory on that server", "روی آن سرور حافظه آزاد کنید", false)
		}
		// the load average alone is no proof: many short-lived threads (Go cores, an
		// emulator) push it past 2× the cores while half the CPU is idle. Busy time is.
		if s.NProc > 0 && (s.CPU >= dcCPUBusy || s.CPU < 0 && s.Load > float64(2*s.NProc)) {
			busy, busyFa := "", ""
			if s.CPU >= 0 {
				busy, busyFa = fmt.Sprintf("%d%% busy, ", s.CPU), fmt.Sprintf("%d%% مشغول، ", s.CPU)
			}
			return res(sideID(s), "cpu",
				fmt.Sprintf("%s: the CPU is overloaded (%sload %.1f on %d cores)", s.name(), busy, s.Load, s.NProc),
				fmt.Sprintf("%s: پردازنده بیش از حد درگیر است (%sبار %.1f روی %d هسته)", s.nameFa(), busyFa, s.Load, s.NProc),
				"find what keeps that server's CPU busy", "ببینید چه چیزی پردازنده‌ی آن سرور را درگیر کرده", false)
		}
		// the core itself can't keep up: its queue toward the tun interface overflows
		if n, l := dcCountRecent(s, dcSlowRe, now-int64(dcRecent/time.Second)); n >= dcSlowMin {
			en, fa := "", ""
			if s.Emulated {
				en, fa = " — it is an x86 build running under emulation on this ARM server, which is much slower", " — نسخه‌ی x86 است که روی این سرور ARM زیر شبیه‌ساز اجرا می‌شود و خیلی کندتر است"
			}
			return res(sideID(s), "core_slow",
				fmt.Sprintf("%s: the %s can't keep up and drops packets (its queue is full: %d times in its recent log)%s", s.name(), core, n, en),
				fmt.Sprintf("%s: %s از پس ترافیک برنمی‌آید و بسته‌ها را دور می‌ریزد (صفش پر است: %d بار در لاگ اخیرش)%s", s.nameFa(), coreFa, n, fa),
				"keep the users on a lighter path on this server, or give the server more CPU", "کاربران را روی مسیر سبک‌تری روی این سرور نگه دارید، یا پردازنده‌ی سرور را بیشتر کنید", false, dcEv(s, l))
		}
		if len(s.OOM) > 0 {
			return res(sideID(s), "oom_other",
				s.name()+": the kernel killed programs for lack of memory in the last 3 h",
				s.nameFa()+": کرنل در ۳ ساعت اخیر برنامه‌هایی را به خاطر کمبود حافظه کشته است",
				"free memory on that server, then restart this path", "روی آن سرور حافظه آزاد کنید، بعد مسیر را ری‌استارت کنید", true, s.Where+" kernel: "+hsRedact(s.OOM[len(s.OOM)-1]))
		}
	}

	// 8. a panel job on the tunnel right before the drop
	if j := in.Job; j != nil && in.DownAt > 0 {
		end := j.Ended
		if end == 0 {
			end = now
		}
		if j.Started <= in.DownAt+60 && end >= in.DownAt-600 {
			at := time.Unix(j.Started, 0).UTC().Format("15:04")
			return res("panel", "panel_job",
				fmt.Sprintf("it went down during or right after the panel's “%s” on this tunnel (started %s UTC)", j.Kind, at),
				fmt.Sprintf("حین یا درست بعد از «%s» پنل روی این تانل قطع شد (شروع %s UTC)", j.Kind, at),
				"if it doesn't come back in a few minutes, restart this path", "اگر تا چند دقیقه برنگشت، مسیر را ری‌استارت کنید", true)
		}
	}

	// weak signs the core logged recently: no proof, but what it sees
	for _, s := range sides {
		if p, l := keyLine(s, now-int64(dcRecent/time.Second)); p != nil {
			return res(sideID(s), "log_"+p.Code,
				s.name()+": both cores run; the "+core+" logs that "+p.En,
				s.nameFa()+": هر دو هسته اجرا می‌شوند؛ "+coreFa+" در لاگش می‌گوید "+p.Fa,
				actRestartEn, actRestartFa, true, dcEv(s, l))
		}
	}
	ev := []string{}
	for _, s := range sides {
		if s.PingSmall >= 0 {
			ev = append(ev, fmt.Sprintf("test: ping from %s: %d%% lost (big packets: %d%%)", s.Where, s.PingSmall, s.PingBig))
		}
		for _, r := range s.Reach {
			ev = append(ev, fmt.Sprintf("test: TCP connect from %s to port %d: %s", s.Where, r.Port, reachText(&r)))
		}
	}
	return res("", "unknown",
		"both cores run and the servers reach each other, but the switcher's check through this path gets no answer — nothing more could be proven",
		"هر دو هسته اجرا می‌شوند و دو سرور به هم می‌رسند، ولی بررسی سوییچر از این مسیر جوابی نمی‌گیرد — چیز بیشتری ثابت نشد",
		actRestartEn, actRestartFa, true, ev...)
}

func pk(n int64) string {
	if n < 0 {
		return "?"
	}
	return strconv.FormatInt(n, 10)
}

func inInts(l []int, x int) bool {
	for _, v := range l {
		if v == x {
			return true
		}
	}
	return false
}

func fmtStates(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	var s []string
	for k, v := range m {
		s = append(s, fmt.Sprintf("%d %s", v, k))
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}

func reachText(r *dcReach) string {
	switch r.RC {
	case 0:
		return fmt.Sprintf("connected in %d ms", r.MS)
	case 124:
		return "timed out (4 s)"
	default:
		return fmt.Sprintf("refused or unreachable after %d ms", r.MS)
	}
}

// dcLastLines: the side's last n log lines that match a pattern, for the evidence.
func dcLastLines(s *dcSide, mid string, n int) []string {
	var out []string
	for i := len(s.Journal) - 1; i >= 0 && len(out) < n; i-- {
		if dcMatch(mid, s.Journal[i].Text) != nil {
			out = append([]string{dcEv(s, s.Journal[i])}, out...)
		}
	}
	return out
}

// dcFirewall says when the listening side's own firewall may drop the port.
func dcFirewall(s *dcSide, ports []int) (string, string) {
	for _, r := range s.InDrop {
		for _, p := range ports {
			if dcRuleHits(r, "tcp", p) {
				return s.Where + "'s firewall has a DROP/REJECT rule for port " + strconv.Itoa(p), "فایروال " + s.WhereFa + " برای پورت " + strconv.Itoa(p) + " قانون DROP/REJECT دارد"
			}
		}
	}
	if strings.Contains(strings.ToLower(s.UFW), "status: active") {
		return "ufw is active on " + s.Where + " and may drop it", "ufw روی " + s.WhereFa + " فعال است و ممکن است دورش بریزد"
	}
	return "", ""
}

var (
	dcDportRe  = regexp.MustCompile(`--dport (\d+)(?::(\d+))?`)
	dcDportsRe = regexp.MustCompile(`--dports (\S+)`)
	dcProtoRe  = regexp.MustCompile(`-p (\w+)`)
)

// dcRuleHits: an iptables -S rule matches proto/port (no port match = every port).
func dcRuleHits(rule, proto string, port int) bool {
	if m := dcProtoRe.FindStringSubmatch(rule); m != nil && m[1] != proto && m[1] != "all" {
		return false
	}
	if m := dcDportRe.FindStringSubmatch(rule); m != nil {
		lo, _ := strconv.Atoi(m[1])
		hi := lo
		if m[2] != "" {
			hi, _ = strconv.Atoi(m[2])
		}
		return port >= lo && port <= hi
	}
	if m := dcDportsRe.FindStringSubmatch(rule); m != nil {
		for _, x := range strings.Split(m[1], ",") {
			a, b, rng := strings.Cut(x, ":")
			lo, _ := strconv.Atoi(a)
			hi := lo
			if rng {
				hi, _ = strconv.Atoi(b)
			}
			if port >= lo && port <= hi {
				return true
			}
		}
		return false
	}
	// no port: limited by something else (an address, an interface) the panel can't judge
	return false
}

// dcExempt: a raw NOTRACK rule for the port keeps NAT off it (the panel's own fix for
// carriers that share a port with a REDIRECT, PR 152).
func dcExempt(raw []string, port int) bool {
	for _, r := range raw {
		if dcRuleHits(r, "tcp", port) || strings.Contains(r, "--sport "+strconv.Itoa(port)) {
			return true
		}
	}
	return false
}

// dcRuleShort: "chain IGPX: tcp 80,443 → REDIRECT 12346".
func dcRuleShort(r string) string {
	f := strings.Fields(r)
	chain := ""
	if len(f) > 1 && f[0] == "-A" {
		chain = f[1]
	}
	what := ""
	if m := dcProtoRe.FindStringSubmatch(r); m != nil {
		what = m[1]
	}
	if m := dcDportRe.FindStringSubmatch(r); m != nil {
		what += " " + strings.TrimPrefix(m[0], "--dport ")
	} else if m := dcDportsRe.FindStringSubmatch(r); m != nil {
		what += " " + m[1]
	}
	tgt := ""
	if i := strings.Index(r, "-j "); i >= 0 {
		tgt = hsRedact(strings.TrimSpace(r[i+3:]))
		tgt = strings.Join(strings.Fields(strings.NewReplacer("--to-ports", "", "--to-destination", "→").Replace(tgt)), " ")
	}
	return strings.TrimSpace("chain " + chain + ": " + strings.TrimSpace(what) + " → " + tgt)
}

// dcIPProto: methods whose packets between the servers are a bare IP protocol (GRE 47,
// ESP 50) — no TCP, UDP or ICMP.
func dcIPProto(mid string) bool { return mid == "gre" || mid == "espsk" }

// dcProtoFilter: the cause "this route lets only GRE/ESP through" (nil when not proven).
func dcProtoFilter(in *dcInput, core, coreFa string, extra []string) *dcResult {
	if dcIPProto(in.Method) || len(in.UpVia) == 0 || in.UpOther || in.IR.PingSmall != 100 || in.KH.PingSmall >= 0 && in.KH.PingSmall != 100 {
		return nil
	}
	var ev []string
	for _, s := range []*dcSide{in.IR, in.KH} {
		for _, r := range s.Reach {
			if r.RC != 124 {
				return nil // a TCP connect between the servers got an answer: not this filter
			}
			ev = append(ev, fmt.Sprintf("test: TCP connect from %s to port %d: %s", s.Where, r.Port, reachText(&r)))
		}
		if s.PingSmall >= 0 {
			ev = append(ev, fmt.Sprintf("test: ping from %s to %s: %d%% lost", s.Where, map[bool]string{true: "the foreign server", false: "the Iran server"}[s == in.IR], s.PingSmall))
		}
	}
	via := strings.Join(in.UpVia, ", ")
	ev = append([]string{"working on the same route now: " + via}, ev...)
	return &dcResult{side: "route", code: "proto_filter",
		en: fmt.Sprintf("not possible on this route: it lets only GRE/ESP through (%s works on it), while ping, TCP and UDP between the two servers are dropped — the %s needs TCP or UDP, so it can't work here; the path itself isn't broken", via, core),
		fa: fmt.Sprintf("روی این مسیر شدنی نیست: این مسیر فقط GRE/ESP را رد می‌کند (%s رویش کار می‌کند)، ولی پینگ و TCP و UDP بین دو سرور دور ریخته می‌شود — %s به TCP یا UDP نیاز دارد و اینجا کار نمی‌کند؛ خود مسیر خراب نیست", via, coreFa),
		act: "remove this path from the tunnel (⋯ → 🗑 Remove path) — the panel no longer restarts it. What works on this route: Plain GRE and IPsec static-key (ESP); reverse, TCP and UDP methods only with a foreign server on another provider",
		actFa: "این مسیر را از تانل حذف کنید (⋯ ← 🗑 حذف مسیر) — پنل دیگر ری‌استارتش نمی‌کند. روی این مسیر فقط GRE ساده و IPsec کلید ثابت (ESP) کار می‌کند؛ روش‌های معکوس، TCP و UDP فقط با سرور خارج روی ارائه‌دهنده‌ی دیگر",
		ev: append(ev, extra...)}
}

// dcUpVia: the labels of tunnel id's working GRE/ESP paths of family fam (switcher's view),
// and whether another of its paths of that family works too.
func (a *App) dcUpVia(id, fam string) (out []string, other bool) {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	v := a.hsViews[id]
	if v == nil {
		return nil, false
	}
	for k, key := range v.Keys {
		mid, f, _ := strings.Cut(key, "|")
		if k < len(v.OK) && v.OK[k] && f == fam && !dcIPProto(mid) {
			other = true
		}
		if k < len(v.OK) && v.OK[k] && f == fam && dcIPProto(mid) {
			name := key
			if k < len(v.Paths) {
				name = v.Paths[k]
			}
			out = append(out, name)
		}
	}
	return out, other
}

// ---- running it ----

// dcProto names the packets an L3 method sends between the servers.
func dcProto(mid string) string {
	switch mid {
	case "gre", "golden":
		return "GRE"
	case "espsk", "ipsec6":
		return "ESP"
	case "wg":
		return "UDP (WireGuard)"
	case "icmp":
		return "ICMP"
	case "direct6":
		return "IPv6-in-IPv6"
	case "premium":
		return "TCP"
	}
	return "tunnel"
}

// dcFind looks for the cause of path p of t being down (read-only, ~10-20 s).
func (a *App) dcFind(ctx context.Context, t *Tunnel, p HSPath, downAt int64) (*DownCause, error) {
	var pt *Tunnel
	var probe int
	a.store.View(func(*State) { pt = pathTunnel(t, p); probe = hsProbePort(t) })
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return nil, fmt.Errorf("Iran server not found")
	}
	var fsrv *Server
	if t.ForeignID != "" {
		fsrv = a.store.Server(t.ForeignID)
	}
	d := deriveFor(pt, srv, fsrv, a.settings())
	m := methodByID[p.Method]
	if m == nil {
		return nil, fmt.Errorf("unknown method %s", p.Method)
	}
	l3 := benchIsL3(m, pt.Options[m.ID])
	unit := unitName(pt)
	fname := "this panel host"
	if fsrv != nil {
		fname = fsrv.Name
	}
	in := &dcInput{Method: p.Method, Family: p.Family, Title: m.Title, L3: l3, Proto: dcProto(p.Method),
		ProbePort: probe, DownAt: downAt, Now: time.Now(),
		IfaceKnown: inList([]string{"gre", "ipsec6", "direct6", "espsk", "wg", "golden", "bp_l3"}, p.Method),
		IR:         newDCSide("Iran server", "سرور ایران", srv.Name, d.KHPub),
		KH:         newDCSide("foreign server", "سرور خارج", fname, d.IRPub)}
	in.Internal = [2]int{hsInternal(p, 0), hsInternal(p, 19)}
	iface, inner := "", ""
	if l3 {
		in.Proto = dcProto(p.Method)
		if in.IfaceKnown {
			iface = d.Iface
		}
		inner = d.KHv4
	} else {
		in.FwdPort = hsInternal(p, 19)
	}
	in.Job = a.jobs.latestFor(t.ID)
	in.UpVia, in.UpOther = a.dcUpVia(t.ID, p.Family)

	type side struct {
		s     *dcSide
		h     Host
		probe int
		fwd   int
		inner string
	}
	var sides [2]side
	var wg sync.WaitGroup
	for i := range sides {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var h Host
			var err error
			if i == 0 {
				h, _, err = a.reach(ctx, srv, nil)
				sides[i] = side{s: in.IR, fwd: in.FwdPort, inner: inner}
			} else {
				h, _, err = a.foreignHost(ctx, t, nil)
				sides[i] = side{s: in.KH, probe: probe}
			}
			sides[i].h = h
			if err != nil || h == nil {
				sides[i].s.Err = fmt.Sprint(orErr(err)) // "failed" when there was no error but no host either
				return
			}
			out, err := h.Run(ctx, dcFactsScript(unit, sides[i].s.Peer, sides[i].probe, sides[i].fwd, iface, sides[i].inner), nil)
			if err != nil && !strings.Contains(out, "TS ") {
				sides[i].s.Err = err.Error()
				return
			}
			dcParse(sides[i].s, out)
		}(i)
	}
	wg.Wait()
	// round 2: each side connects to the other's TCP ports; the interfaces are sampled again
	listens := func(s *dcSide, internal bool) []int {
		var ps []int
		for _, k := range s.Socks {
			if k.Proto == "tcp" && k.State == "LISTEN" && !strings.HasPrefix(k.LAddr, "127.") && k.LAddr != "::1" && !inInts(ps, k.LPort) &&
				!(internal && k.LPort >= in.Internal[0] && k.LPort <= in.Internal[1]) && k.LPort != probe && len(ps) < 3 {
				ps = append(ps, k.LPort)
			}
		}
		return ps
	}
	targets := [2][]int{listens(in.KH, false), listens(in.IR, true)}
	for i := range sides {
		if sides[i].s.Err != "" || sides[i].h == nil || (len(targets[i]) == 0 && iface == "") {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if out, err := sides[i].h.Run(ctx, dcReachScript(sides[i].s.Peer, targets[i], iface), nil); err == nil || out != "" {
				dcParse(sides[i].s, out)
			}
		}(i)
	}
	wg.Wait()
	return dcClassify(in).cause(p.Method+"|"+p.Family, in), nil
}

// dcSchedule starts a hunt for each down path of t whose cause isn't known for this
// outage (or is older than dcEvery), and forgets the causes of paths that are up again.
func (a *App) dcSchedule(t *Tunnel, v *hsView) {
	if v == nil || len(v.Keys) != len(v.OK) {
		return
	}
	var applying string
	var paths []HSPath
	a.store.View(func(*State) { applying = t.Applying; paths = hsGood(t) })
	if applying != "" {
		return
	}
	now := time.Now()
	type due struct {
		p      HSPath
		downAt int64
	}
	var start []due
	a.healthMu.Lock()
	if a.dc.cache == nil {
		a.dc = dcState{cache: map[string]*DownCause{}, busy: map[string]bool{}, tried: map[string]time.Time{}}
	}
	for k, key := range v.Keys {
		id := t.ID + "|" + key
		if v.OK[k] {
			delete(a.dc.cache, id)
			continue
		}
		var downAt int64
		if k < len(v.Changed) {
			downAt = v.Changed[k]
		}
		c := a.dc.cache[id]
		if c != nil && c.DownAt == downAt && now.Sub(time.Unix(c.At, 0)) < dcEvery {
			continue
		}
		if a.dc.busy[id] || now.Sub(a.dc.tried[id]) < dcMinGap {
			continue
		}
		for _, p := range paths {
			if p.Method+"|"+p.Family == key {
				start = append(start, due{p, downAt})
				a.dc.busy[id] = true
				a.dc.tried[id] = now
			}
		}
	}
	a.healthMu.Unlock()
	for _, d := range start {
		go a.dcRun(t, d.p, d.downAt)
	}
}

func (a *App) dcRun(t *Tunnel, p HSPath, downAt int64) {
	id := t.ID + "|" + p.Method + "|" + p.Family
	defer func() {
		a.healthMu.Lock()
		delete(a.dc.busy, id)
		a.healthMu.Unlock()
	}()
	select {
	case dcSem <- struct{}{}:
		defer func() { <-dcSem }()
	default:
		a.healthMu.Lock()
		delete(a.dc.tried, id) // try again on the next read
		a.healthMu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	c, err := a.dcFind(ctx, t, p, downAt)
	if err != nil || c == nil {
		return
	}
	a.healthMu.Lock()
	a.dc.cache[id] = c
	a.healthMu.Unlock()
}

// dcForget drops a path's cause (after a restart: the next read looks again).
func (a *App) dcForget(t *Tunnel, key string) {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	if a.dc.cache != nil {
		delete(a.dc.cache, t.ID+"|"+key)
		delete(a.dc.tried, t.ID+"|"+key)
	}
}

// hsViewCause is hsViewOf with the known causes of its down paths, one per path (a copy:
// the cached view is shared).
func (a *App) hsViewCause(id string) *hsView {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	v := a.hsViews[id]
	if v == nil || a.dc.cache == nil {
		return v
	}
	cp := *v
	cp.Cause = make([]*DownCause, len(v.Keys))
	found := false
	for k, key := range v.Keys {
		if k < len(v.OK) && !v.OK[k] {
			if c := a.dc.cache[id+"|"+key]; c != nil {
				cp.Cause[k], found = c, true
			}
		}
	}
	if !found {
		cp.Cause = nil
	}
	return &cp
}

// hsRestartJob restarts only path (mid, fam)'s cores on both servers, as a short job: the
// fix a cause like "the core is stuck" suggests. Not the users' path (move them first):
// their connections on it would be cut.
func (a *App) hsRestartJob(t *Tunnel, mid, fam string) (*Job, error) {
	key := mid + "|" + fam
	var p HSPath
	found := false
	a.store.View(func(*State) {
		for _, x := range hsGood(t) {
			if x.Method+"|"+x.Family == key {
				p, found = x, true
			}
		}
	})
	if !found {
		return nil, fmt.Errorf("this path isn't running on the tunnel")
	}
	if v := a.hsViewOf(t.ID); v != nil && v.Active >= 0 && v.Active < len(v.Keys) && v.Keys[v.Active] == key {
		return nil, fmt.Errorf("the users are on this path — move them to another one with “use” first")
	}
	j, err := a.jobs.start(t.ID, "restart")
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(2 * time.Minute)
		defer cancel()
		j.log("restarting only %s's cores on both servers — the switcher, the other paths and the users are left alone", p.label())
		a.hsKickNoted(t, key, time.Now())
		if err := a.hsRestartPath(ctx, t, p); err != nil {
			j.log("ERROR: %v", err)
			j.finish("error")
			return
		}
		a.dcForget(t, key)
		j.log("DONE — restarted; the switcher checks it again within seconds")
		j.finish("ok")
	}()
	return j, nil
}

// dcLog writes a cause into a job's log (Diagnose).
func dcLog(j *Job, c *DownCause) {
	j.log("    → cause: %s", c.Text)
	for _, e := range c.Evidence {
		j.log("      · %s", e)
	}
	if c.Action != "" {
		j.log("      what to do: %s", c.Action)
	}
}

// dcSlowRe: a core whose own queue overflows (Backhaul Premium's NetToTun/TunToNet channel)
var dcSlowRe = regexp.MustCompile(`(?i)channel full, dropping packet|worker \d+ dropped packet`)

// dcCountRecent counts a side's log lines since from that match re, and returns the newest.
func dcCountRecent(s *dcSide, re *regexp.Regexp, from int64) (int, dcLine) {
	n := 0
	var last dcLine
	for _, l := range s.Journal {
		if l.At > 0 && l.At < from || !re.MatchString(l.Text) {
			continue
		}
		n++
		last = l
	}
	return n, last
}
