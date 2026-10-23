package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Settings describes the foreign (local) server the panel runs on.
type Settings struct {
	LocalIPv4   string `json:"localIPv4"`
	LocalIPv6   string `json:"localIPv6"`
	PanelName   string `json:"panelName"`
	FRPVersion  string `json:"frpVersion"`  // empty = latest
	GitHubProxy string `json:"githubProxy"` // optional prefix, e.g. https://ghproxy.example/
	// AgentConnect is the host:port the Iran agent dials back to (this foreign
	// server's public address + agent port). Shown in the bootstrap command.
	AgentConnect  string `json:"agentConnect"`
	TelegramTok   string `json:"telegramTok"`
	TelegramAdmin string `json:"telegramAdmin"` // numeric chat id(s), comma-separated
	// AutoBench: hours between automatic benchmarks of every route in use ("" = 12, "0" = off)
	AutoBench string `json:"autoBench"`
	// TelegramBackup "on": the daily backup is also sent to the admin chat
	TelegramBackup string `json:"telegramBackup"`
}

// Server is a remote Iran server reached over SSH.
type Server struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
	SSHHost    string `json:"sshHost"` // address used for SSH (defaults to ipv4 then ipv6)
	SSHPort    int    `json:"sshPort"`
	SSHUser    string `json:"sshUser"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
	HostKey    string `json:"hostKey,omitempty"` // pinned on first connect
	Arch       string `json:"arch,omitempty"`
	OS         string `json:"os,omitempty"`
	Prepared   bool   `json:"prepared"`
	// Provisioned is when every method's binaries/packages were last pre-installed (0 = never).
	Provisioned int64  `json:"provisioned,omitempty"`
	CreatedAt   int64  `json:"createdAt"`
	Role        string `json:"role"`                 // iran | foreign
	AgentToken  string `json:"agentToken,omitempty"` // dial-back agent auth
	// Proxy routes the panel's SSH connection to this server through a SOCKS5 or
	// HTTP CONNECT proxy, e.g. socks5://user:pass@1.2.3.4:1080 or http://1.2.3.4:3128
	Proxy string `json:"proxy,omitempty"`
	// Via, if set, is the id of another server to use as SSH jump host (blank = auto).
	Via      string `json:"via,omitempty"`
	LastPath string `json:"lastPath,omitempty"` // how the panel last reached it
	Country  string `json:"country,omitempty"`  // ISO-3166 alpha-2, for the flag (auto or manual)
	City     string `json:"city,omitempty"`
}

// Tunnel links one Iran server with this (foreign) server.
type Tunnel struct {
	ID        string                       `json:"id"`
	Name      string                       `json:"name"`
	ServerID  string                       `json:"serverId"`  // Iran server
	ForeignID string                       `json:"foreignId"` // foreign server ("" = this panel host)
	Family    string                       `json:"family"`    // v4 | v6 (outer/underlay address family)
	Ports     string                       `json:"ports"`     // e.g. "443,8080=80,2000-2010"
	Index     int                          `json:"index"`     // unique small number used for subnets/ifnames
	Active    string                       `json:"active"`    // active method id ("" = stopped)
	Selected  string                       `json:"selected"`
	Options   map[string]map[string]string `json:"options"` // per-method options (kept when switching)
	Note      string                       `json:"note"`
	LastJob   string                       `json:"lastJob"`
	Updated   int64                        `json:"updated"`
	Secrets   map[string]string            `json:"secrets"` // stable per-tunnel secrets (tokens, PSKs)
	Shape     Shape                        `json:"shape"`   // optional traffic-shaping layer
	// NoFailover turns off automatic failover for this tunnel (on by default).
	NoFailover bool `json:"noFailover,omitempty"`
	// Failover is set while the tunnel runs on a backup path; it remembers the original.
	Failover *FailoverState `json:"failover,omitempty"`
	// HotStandby keeps every compatible path running; a switcher on the Iran server moves
	// the users between them (see hotstandby.go). Paths is the last plan, switcher order.
	HotStandby bool `json:"hotStandby,omitempty"`
	// HSAuto: the switcher also moves users to a clearly better path (speed, loss, latency),
	// not only away from a failed one. Off = manual: the chosen path, unless it is down.
	HSAuto bool `json:"hsAuto,omitempty"`
	// HSPin "method|family": the path chosen in the panel/bot (users moved there without a
	// re-apply); "" = the tunnel's own method.
	HSPin  string   `json:"hsPin,omitempty"`
	Paths  []HSPath `json:"paths,omitempty"`
	HSSeen int64    `json:"hsSeen,omitempty"` // newest switcher event already reported
	// Applying is the method an apply is bringing up, from the moment it tears the old one
	// down until it ends. Still set at start-up = the panel stopped in the middle (restart,
	// update) and the tunnel was left down: resumeInterrupted brings it back.
	Applying string `json:"applying,omitempty"`
}

// Shape is an optional per-tunnel traffic-shaping layer applied with tc + iptables on the
// Iran egress (ported from the "backhaul-dpi" tc script). It is independent of the method.
type Shape struct {
	Enabled bool   `json:"enabled"`
	Qdisc   string `json:"qdisc"`  // cake | htb | tbf | fq_codel
	Jitter  bool   `json:"jitter"` // add netem delay/jitter on top
	MSS     int    `json:"mss"`    // TCP MSS clamp on the egress (0 = off)
	Iface   string `json:"iface"`  // egress interface ("" = default route device)
	OnBoth  bool   `json:"onBoth"` // also shape the foreign egress
}

// setOption sets one method option copy-on-write (readers outside the store lock keep a
// consistent map). Call it inside store.Update.
func (t *Tunnel) setOption(mid, key, val string) {
	no := make(map[string]map[string]string, len(t.Options)+1)
	for k, v := range t.Options {
		no[k] = v
	}
	inner := make(map[string]string, len(no[mid])+1)
	for k, v := range no[mid] {
		inner[k] = v
	}
	inner[key] = val
	no[mid] = inner
	t.Options = no
}

// clone is a deep copy safe to use after the store lock is released.
func (t *Tunnel) clone() Tunnel {
	cp := *t
	cp.Options = make(map[string]map[string]string, len(t.Options))
	for k, v := range t.Options {
		in := make(map[string]string, len(v))
		for a, b := range v {
			in[a] = b
		}
		cp.Options[k] = in
	}
	cp.Paths = make([]HSPath, len(t.Paths))
	for i, p := range t.Paths {
		cp.Paths[i] = p
		if p.Opts != nil {
			cp.Paths[i].Opts = make(map[string]string, len(p.Opts))
			for k, v := range p.Opts {
				cp.Paths[i].Opts[k] = v
			}
		}
	}
	cp.Secrets = make(map[string]string, len(t.Secrets))
	for k, v := range t.Secrets {
		cp.Secrets[k] = v
	}
	if t.Failover != nil {
		f := *t.Failover
		cp.Failover = &f
	}
	return cp
}

// secret returns a stable random secret for the given key, creating it once.
// Not persisted here; the caller persists the tunnel after building.
func (t *Tunnel) secret(key string) string {
	if t.Secrets == nil {
		t.Secrets = map[string]string{}
	}
	if v, ok := t.Secrets[key]; ok && v != "" {
		return v
	}
	v := randHex(24)
	// copy-on-write: other goroutines may be reading the current map
	ns := make(map[string]string, len(t.Secrets)+1)
	for k, x := range t.Secrets {
		ns[k] = x
	}
	ns[key] = v
	t.Secrets = ns
	return v
}

type User struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
	// Gen is part of every session's signature: sign-out and a password change bump it, so
	// the sessions issued before stop working (a stolen cookie included)
	Gen int `json:"gen,omitempty"`
}

type State struct {
	Settings Settings  `json:"settings"`
	Users    []User    `json:"users"`
	Servers  []*Server `json:"servers"`
	Tunnels  []*Tunnel `json:"tunnels"`
	Secret   string    `json:"secret"`
	// SetupCode is needed to create the first admin account (printed by the installer and
	// in the log), so whoever finds a fresh panel first can't take it over
	SetupCode    string        `json:"setupCode,omitempty"`
	BenchHistory []BenchRecord `json:"benchHistory,omitempty"`
	// RouteSkip: per server pair ("iran|foreign"), the "method|family" paths the user took
	// out — never benchmarked, deployed as a hot-standby path or used for failover there
	RouteSkip map[string][]string `json:"routeSkip,omitempty"`
	// Cleanups: teardowns a server missed while unreachable (see cleanup.go)
	Cleanups []Cleanup `json:"cleanups,omitempty"`
	// LastVersion is the panel version that ran last (a new one repairs tunnels once)
	LastVersion string   `json:"lastVersion,omitempty"`
	Outages     []Outage `json:"outages,omitempty"` // servers/tunnels down, newest last
}

// FailoverState is the original path of a tunnel that was moved to a backup.
type FailoverState struct {
	Method    string `json:"method"`
	Family    string `json:"family"`
	Since     int64  `json:"since"`     // when the backup took over
	LastCheck int64  `json:"lastCheck"` // last time the original was re-tested
	Reason    string `json:"reason"`
}

// BenchRecord is one finished benchmark, kept so you can see which route was tested when.
type BenchRecord struct {
	ID          string        `json:"id"`
	At          int64         `json:"at"`
	IranID      string        `json:"iranId"`
	IranName    string        `json:"iranName"`
	ForeignID   string        `json:"foreignId"`
	ForeignName string        `json:"foreignName"`
	Family      string        `json:"family"`
	Results     []BenchResult `json:"results"`
}

type Store struct {
	mu   sync.Mutex
	path string
	S    State
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// newSetupCode is 12 characters that are easy to read and type (no 0/O, 1/l/I).
func newSetupCode() string {
	const abc = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	out := make([]byte, 0, 14)
	for i, x := range b {
		if i == 4 || i == 8 {
			out = append(out, '-')
		}
		out = append(out, abc[int(x)%len(abc)])
	}
	return string(out)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func LoadStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st := &Store{path: filepath.Join(dir, "state.json")}
	data, err := os.ReadFile(st.path)
	if err == nil {
		if err := json.Unmarshal(data, &st.S); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if st.S.Secret == "" {
		st.S.Secret = randHex(32)
	}
	if len(st.S.Users) == 0 && st.S.SetupCode == "" {
		st.S.SetupCode = newSetupCode()
	}
	if st.S.Settings.PanelName == "" {
		st.S.Settings.PanelName = "Tunnel Panel"
	}
	for _, t := range st.S.Tunnels {
		if t.Options == nil {
			t.Options = map[string]map[string]string{}
		}
	}
	// addresses typed before they were validated ("2a01:..::1/64", "[..]", upper case) would
	// never match the host's own address in the tunnel scripts
	if v, err := normIP(st.S.Settings.LocalIPv4, false); err == nil {
		st.S.Settings.LocalIPv4 = v
	}
	if v, err := normIP(st.S.Settings.LocalIPv6, true); err == nil {
		st.S.Settings.LocalIPv6 = v
	}
	for _, sv := range st.S.Servers {
		if v, err := normIP(sv.IPv4, false); err == nil {
			sv.IPv4 = v
		}
		if v, err := normIP(sv.IPv6, true); err == nil {
			sv.IPv6 = v
		}
	}
	return st, st.saveLocked()
}

// normIP cleans up an address as typed (spaces, brackets, a /prefix or %zone) and checks
// its family; "" stays "".
func normIP(s string, v6 bool) (string, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "["), "]")
	if i := strings.IndexAny(s, "/%"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "", nil
	}
	ip := net.ParseIP(s)
	switch {
	case ip == nil:
		return "", fmt.Errorf("%q is not an IP address", s)
	case v6 && ip.To4() != nil:
		return "", fmt.Errorf("%s is an IPv4 address — put it in the IPv4 field", s)
	case !v6 && ip.To4() == nil:
		return "", fmt.Errorf("%s is an IPv6 address — put it in the IPv6 field", s)
	case ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsUnspecified():
		return "", fmt.Errorf("%s can't be reached from another server — use the server's public address", s)
	}
	return ip.String(), nil
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(&s.S, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Server and Tunnel look up by id under the lock. Inside Update/View callbacks use
// the *Locked variants instead (the lock is not re-entrant).
func (s *Store) Server(id string) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverLocked(&s.S, id)
}

func (s *Store) Tunnel(id string) *Tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tunnelLocked(&s.S, id)
}

func (s *Store) serverLocked(st *State, id string) *Server {
	if id == "" {
		return nil
	}
	for _, x := range st.Servers {
		if x.ID == id {
			return x
		}
	}
	return nil
}

func (s *Store) tunnelLocked(st *State, id string) *Tunnel {
	for _, x := range st.Tunnels {
		if x.ID == id {
			return x
		}
	}
	return nil
}

// nextIndexLocked picks the smallest free tunnel index (1..249; 250+ reserved for benchmarks).
func (s *Store) nextIndexLocked(st *State) int {
	used := pendingIndices(st) // numbers whose leftovers still sit on an unreachable server
	for _, t := range st.Tunnels {
		used[t.Index] = true
		for _, p := range t.Paths {
			used[p.Index] = true
		}
	}
	for i := 1; i < 250; i++ {
		if !used[i] {
			return i
		}
	}
	return 0 // all 249 slots taken (250 is the benchmark's): the caller refuses
}

// Update runs fn under the store lock and persists the result.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.S); err != nil {
		return err
	}
	return s.saveLocked()
}

// View runs fn under the store lock without saving.
func (s *Store) View(fn func(*State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.S)
}
