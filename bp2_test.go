package main

import (
	"strings"
	"testing"
)

func bp2Confs(t *testing.T, m *Method, tn *Tunnel) (string, string) {
	t.Helper()
	srv := &Server{ID: "ir", IPv4: "192.0.2.10", IPv6: "2001:db8::10"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.20", IPv6: "2001:db8::20", Role: "foreign"}
	ir, kh, err := buildPlans(m, tn, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := tunnelDir(tn) + "/tp-" + tn.ID + ".toml"
	for _, p := range []SidePlan{ir, kh} {
		// v2 never replaces the v1 binary: a running v1 tunnel keeps the build it was made with
		if p.Files[cfg].Mode != 0o600 || len(p.Artifacts) != 1 || p.Artifacts[0].Dest != "/usr/local/bin/backpack2" ||
			p.Artifacts[0].Name != "backpack-v2.0.0" || !strings.HasPrefix(p.Unit.ExecStart, "/usr/local/bin/backpack2 -c ") ||
			!strings.Contains(p.Setup, "/usr/local/bin/backpack2 check -c "+cfg) {
			t.Fatalf("v2 plan must run its own binary: %+v %q %q", p.Artifacts, p.Unit.ExecStart, p.Setup)
		}
	}
	return string(ir.Files[cfg].Content), string(kh.Files[cfg].Content)
}

func TestBackpack2Artifact(t *testing.T) {
	a, v1 := artBackpack2(Settings{GitHubProxy: "https://gh.example/"}), artBackpack(Settings{})
	if a.Dest == v1.Dest || a.Name == v1.Name {
		t.Fatalf("v2 shares v1's binary or cache key: %q %q", a.Dest, a.Name)
	}
	for _, want := range []string{
		"https://gh.example/https://github.com/AminMGMT/BackPack/releases/download/v2.0.0/backpack_linux_${ARCH}.tar.gz",
		"amd64) want=6e38749a1d749cbf11eb293457ddc94142a96659350acf6047fc7ef44a6115d3 ;;",
		"arm64) want=7f709943079b257856349ddbb370cdd1b386ea7059e11584d9ae1fcab40616fe ;;",
		"sha256sum -c - || {", "exit 1",
	} {
		if !strings.Contains(a.Fetch, want) {
			t.Errorf("fetch lacks %q:\n%s", want, a.Fetch)
		}
	}
	// only the official repository, and the checksum is checked before anything is unpacked
	if strings.Count(a.Fetch, "github.com/") != 1 || strings.Count(a.Fetch, "github.com/AminMGMT/BackPack/") != 1 ||
		strings.Index(a.Fetch, "sha256sum") > strings.Index(a.Fetch, "tar -xzf") {
		t.Errorf("fetch order / source:\n%s", a.Fetch)
	}
}

func TestBackpack2ReverseBuild(t *testing.T) {
	tn := &Tunnel{ID: "t21", Name: "nl", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "2053,8443=443", Index: 21,
		Options: map[string]map[string]string{"bp2_reverse": {"tunnel_port": "28401"}}}
	s, c := bp2Confs(t, methodBackpack2Reverse, tn)
	tok := tn.Secrets["bp2-token"]
	if len(tok) < 16 || tn.Secrets["bp-token"] != "" {
		t.Fatalf("v2 must have a token of its own: %d chars, v1 token set=%v", len(tok), tn.Secrets["bp-token"] != "")
	}
	common := []string{`transport = "stealth"`, `token = "` + tok + `"`, `peer_auth = "required"`, `preset = "turbo"`, "skip_optz = true",
		"web_port = 0", "nodelay = true", "keepalive_period = 75", "mux_version = 2", "mux_framesize = 32768",
		"mux_recievebuffer = 16777216", "mux_streambuffer = 2097152"}
	mustHave(t, "Iran", s, append(common, "[server]", `bind_addr = "0.0.0.0:28401"`, "heartbeat = 40", "channel_size = 4096", "mux_con = 8",
		"accept_udp = false", `ports = ["2053", "8443=443", "`)...)
	// stealth is no mux transport: turbo gives it the larger pool v2.0.0 introduced
	mustHave(t, "foreign", c, append(common, "[client]", `remote_addr = "192.0.2.10:28401"`, "connection_pool = 16", "aggressive_pool = false",
		"retry_interval = 3", "dial_timeout = 10")...)
	if strings.Contains(s+c, "kcp_") || strings.Contains(c, "ports") || strings.Contains(s, "connection_pool") {
		t.Errorf("keys on the wrong side or transport:\n%s\n%s", s, c)
	}

	// a mux transport keeps the preset's pool; aggressive raises pool, windows and buffers
	tn.Options["bp2_reverse"] = map[string]string{"transport": "wsmux", "preset": "aggressive", "accept_udp": "true"}
	s, c = bp2Confs(t, methodBackpack2Reverse, tn)
	mustHave(t, "Iran wsmux", s, `transport = "wsmux"`, "heartbeat = 25", "channel_size = 8192", "mux_con = 16", "accept_udp = true", "keepalive_period = 60")
	mustHave(t, "foreign wsmux", c, "connection_pool = 16", "aggressive_pool = true", "mux_framesize = 65535")

	// kcp reads the kcp_* keys, and is the only transport of the throughput preset
	tn.Options["bp2_reverse"] = map[string]string{"transport": "kcp", "preset": "throughput"}
	s, c = bp2Confs(t, methodBackpack2Reverse, tn)
	for _, conf := range []string{s, c} {
		mustHave(t, "kcp", conf, "kcp_mtu = 1250", "kcp_interval = 20", "kcp_acknodelay = false", "kcp_sndwnd = 4096", "kcp_rcvwnd = 4096",
			"kcp_datashards = 10", "kcp_parityshards = 1", "kcp_nocongestion = 1")
	}
	srv, fsrv := &Server{ID: "ir", IPv4: "192.0.2.10", IPv6: "2001:db8::10"}, &Server{ID: "kh", IPv4: "198.51.100.20", IPv6: "2001:db8::20", Role: "foreign"}
	for _, bad := range []map[string]string{{"transport": "stealth", "preset": "throughput"}, {"transport": "naive"}, {"preset": "max"}} {
		tn.Options["bp2_reverse"] = bad
		if _, _, err := buildPlans(methodBackpack2Reverse, tn, srv, fsrv, Settings{}); err == nil {
			t.Errorf("%v must be refused", bad)
		}
	}

	// IPv6: bracketed addresses; pck and xdi are IPv4-only
	tn6 := &Tunnel{ID: "t22", Name: "nl6", ServerID: "ir", ForeignID: "kh", Family: "v6", Ports: "443", Index: 22}
	s6, c6 := bp2Confs(t, methodBackpack2Reverse, tn6)
	port := portOr("", deriveFor(tn6, srv, fsrv, Settings{}).BasePort)
	mustHave(t, "Iran v6", s6, `bind_addr = "[::]:`+port+`"`)
	mustHave(t, "foreign v6", c6, `remote_addr = "[2001:db8::10]:`+port+`"`)
	tn6.Options = map[string]map[string]string{"bp2_reverse": {"transport": "pck"}}
	if _, _, err := buildPlans(methodBackpack2Reverse, tn6, srv, fsrv, Settings{}); err == nil || !strings.Contains(err.Error(), "IPv4-only") {
		t.Errorf("pck over IPv6: %v", err)
	}
}

func TestBackpack2ReversePck(t *testing.T) {
	tn := &Tunnel{ID: "t23", Name: "tr", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 23,
		Options: map[string]map[string]string{"bp2_rpck": {"tunnel_port": "28402"}}}
	s, c := bp2Confs(t, methodBackpack2RPck, tn)
	kcp := []string{`transport = "pck"`, "kcp_mtu = 1250", "kcp_nodelay = 1", "kcp_interval = 10", "kcp_resend = 2", "kcp_nocongestion = 1",
		"kcp_acknodelay = true", "kcp_sndwnd = 1024", "kcp_rcvwnd = 1024", "kcp_datashards = 10", "kcp_parityshards = 3"}
	mustHave(t, "Iran", s, append(kcp, `bind_addr = "0.0.0.0:28402"`, "mux_con = 8")...)
	mustHave(t, "foreign", c, append(kcp, `remote_addr = "192.0.2.10:28402"`, "connection_pool = 16")...)
	// no port given: pck takes the slot's second port, never the one a TCP tunnel just left
	tn.Options = nil
	srv, fsrv := &Server{ID: "ir", IPv4: "192.0.2.10"}, &Server{ID: "kh", IPv4: "198.51.100.20", Role: "foreign"}
	d := deriveFor(tn, srv, fsrv, Settings{})
	want := portOr("", d.BasePort+1)
	s, c = bp2Confs(t, methodBackpack2RPck, tn)
	mustHave(t, "Iran auto port", s, `bind_addr = "0.0.0.0:`+want+`"`)
	mustHave(t, "foreign auto port", c, `remote_addr = "192.0.2.10:`+want+`"`)
	get, _ := resolveOptions(methodBackpack2RPck, nil)
	if irL, khL := tunnelListenPort(methodBackpack2RPck, tn, get, d); irL != want || khL != "" {
		t.Errorf("the firewall must open the port the tunnel uses: iran %q foreign %q, want %q", irL, khL, want)
	}
	get, _ = resolveOptions(methodBackpack2Reverse, map[string]string{"transport": "pck"})
	if irL, _ := tunnelListenPort(methodBackpack2Reverse, tn, get, d); irL != want {
		t.Errorf("bp2_reverse over pck listens on %q, want %q", irL, want)
	}
	get, _ = resolveOptions(methodBackpack2Reverse, nil)
	if irL, _ := tunnelListenPort(methodBackpack2Reverse, tn, get, d); irL != portOr("", d.BasePort) {
		t.Errorf("bp2_reverse over stealth listens on %q, want the slot's first port", irL)
	}
	if inList(methodBackpack2RPck.Families, "v6") {
		t.Error("pck is IPv4-only")
	}
	// raw packets, no TCP dial: the reverse preflight must not try to connect to it
	if _, ok := reverseTCPPort(methodBackpack2RPck, tn); ok {
		t.Error("bp2_rpck is no TCP dial")
	}
	tn2 := &Tunnel{ID: "t24", Family: "v4", Options: map[string]map[string]string{"bp2_reverse": {"transport": "wsmux"}}}
	if key, ok := reverseTCPPort(methodBackpack2Reverse, tn2); !ok || key != "tunnel_port" {
		t.Errorf("bp2_reverse wsmux dials Iran over TCP: %q %v", key, ok)
	}
	tn2.Options["bp2_reverse"]["transport"] = "kcp"
	if _, ok := reverseTCPPort(methodBackpack2Reverse, tn2); ok {
		t.Error("kcp is UDP")
	}
}

func TestBackpack2DirectPck(t *testing.T) {
	tn := &Tunnel{ID: "t25", Name: "us", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "2053,8443=443", Index: 25,
		Options: map[string]map[string]string{"bp2_pck": {"port": "28403", "conns": "4", "accept_udp": "true"}}}
	s, c := bp2Confs(t, methodBackpack2Pck, tn)
	tok := tn.Secrets["bp2-pck-token"]
	if len(tok) < 16 {
		t.Fatalf("token %d chars", len(tok))
	}
	// Iran dials and holds the users' ports; the foreign side only listens for the segments
	mustHave(t, "Iran", s, "[l3]", `mode = "dial"`, `addr = "198.51.100.20:28403"`, `token = "`+tok+`"`, `carrier = "pck"`, `preset = "turbo"`,
		"pck_conns = 4", "accept_udp = true", `ports = ["2053", "8443=443", "`)
	mustHave(t, "foreign", c, "[l3]", `mode = "listen"`, `addr = "0.0.0.0:28403"`, `token = "`+tok+`"`, `carrier = "pck"`, `preset = "turbo"`, "pck_conns = 4")
	// 1250 on both ends unless asked otherwise: BackPack's 1350 dies in silence on a path under 1402
	mustHave(t, "Iran", s, "pck_kcp_mtu = 1250")
	mustHave(t, "foreign", c, "pck_kcp_mtu = 1250")
	tn.Options["bp2_pck"]["kcp_mtu"] = "1150"
	s, c = bp2Confs(t, methodBackpack2Pck, tn)
	mustHave(t, "Iran", s, "pck_kcp_mtu = 1150")
	mustHave(t, "foreign", c, "pck_kcp_mtu = 1150")
	if alts := methodBackpack2Pck.Alts("v4"); len(alts) == 0 || alts[0]["kcp_mtu"] != "1150" {
		t.Errorf("the benchmark must try smaller packets: %v", alts)
	}
	if strings.Contains(c, "ports") || strings.Contains(s+c, "local_ip") || strings.Contains(s+c, "iface") {
		t.Errorf("direct PCK has no TUN and the foreign side forwards nothing itself:\n%s\n%s", s, c)
	}
	srv, fsrv := &Server{ID: "ir", IPv4: "192.0.2.10"}, &Server{ID: "kh", IPv4: "198.51.100.20", Role: "foreign"}
	d := deriveFor(tn, srv, fsrv, Settings{})
	get, _ := resolveOptions(methodBackpack2Pck, tn.Options["bp2_pck"])
	if irL, khL := tunnelListenPort(methodBackpack2Pck, tn, get, d); irL != "" || khL != "28403" {
		t.Errorf("listen ports: iran %q foreign %q", irL, khL)
	}
	if benchIsL3(methodBackpack2Pck, nil) || !userspaceIran(methodBackpack2Pck, tn) {
		t.Error("direct PCK is a port forwarder that binds the users' ports on Iran")
	}
	// the preset's own session count when none is given
	delete(tn.Options["bp2_pck"], "conns")
	if s, _ = bp2Confs(t, methodBackpack2Pck, tn); strings.Contains(s, "pck_conns") {
		t.Errorf("blank sessions must leave the preset's:\n%s", s)
	}
	for _, bad := range []map[string]string{{"conns": "0"}, {"conns": "17"}, {"conns": "x"}, {"preset": "throughput"}, {"kcp_mtu": "1500"}, {"kcp_mtu": "100"}, {"kcp_mtu": "big"}} {
		tn.Options["bp2_pck"] = bad
		if _, _, err := buildPlans(methodBackpack2Pck, tn, srv, fsrv, Settings{}); err == nil {
			t.Errorf("%v must be refused", bad)
		}
	}
	tn.Options, tn.Family = nil, "v6"
	if _, _, err := buildPlans(methodBackpack2Pck, tn, srv, fsrv, Settings{}); err == nil {
		t.Error("IPv6 must be refused")
	}
}

// The v1 methods are untouched by v2: same binary, same ids, same pin.
func TestBackpack2LeavesV1Alone(t *testing.T) {
	if backpackVersion != "v1.8.5" || artBackpack(Settings{}).Dest != "/usr/local/bin/backpack" {
		t.Fatalf("v1 pin changed: %s %s", backpackVersion, artBackpack(Settings{}).Dest)
	}
	for _, id := range []string{"bp_reverse", "bp_l3", "bp_multi", "bp_pckfec", "bp_pckturbo", "bp2_reverse", "bp2_rpck", "bp2_pck"} {
		if m := methodByID[id]; m == nil || m.Group != "BackPack" {
			t.Errorf("%s not registered in the BackPack group", id)
		}
	}
	if shortMethod("bp2_reverse") == "" || shortMethod("bp2_rpck") == "" || shortMethod("bp2_pck") == "" {
		t.Error("the bot has no name for a v2 method")
	}
}

// A release must not start v2 anywhere by itself: no standby path of a tunnel until someone
// picks it there; once picked it is kept like any other path (plans and Repair leave it in).
func TestBackpack2IsOptIn(t *testing.T) {
	a, st := hsRemoveFixture(t)
	tun := st.Tunnel("aaaaaaaaaaaa")
	ids := []string{"bp2_reverse", "bp2_rpck", "bp2_pck"}
	for _, id := range ids {
		m := methodByID[id]
		if !m.OptIn {
			t.Fatalf("%s must be opt-in", id)
		}
		if a.hsCandidate(tun, m, "v4") {
			t.Errorf("%s became a standby path by itself", id)
		}
		if !a.hsCandidateBase(tun, m, "v4") {
			t.Errorf("%s can't be picked by hand", id)
		}
	}
	for _, p := range a.hsPlan(tun, "gre", "v4") {
		if contains(ids, p.Method) {
			t.Errorf("a plan took %s up by itself", p.Method)
		}
	}
	_, add := a.hsPathDiff(tun)
	for _, p := range add {
		if contains(ids, p.Method) {
			t.Errorf("Repair would add %s by itself", p.Method)
		}
	}
	for _, m := range methods {
		if m.OptIn != contains(ids, m.ID) {
			t.Errorf("%s: opt-in=%v — only the v2 methods are", m.ID, m.OptIn)
		}
	}

	// picked by hand: it is a path of the tunnel now and stays one
	_ = st.Update(func(*State) error {
		tun.Paths = append(tun.Paths, HSPath{Method: "bp2_reverse", Family: "v4", Index: 201})
		return nil
	})
	if !a.hsCandidate(tun, methodByID["bp2_reverse"], "v4") || a.hsCandidate(tun, methodByID["bp2_pck"], "v4") {
		t.Fatal("a picked v2 path must stay a candidate, and only that one")
	}
	kept := false
	for _, p := range a.hsPlan(tun, "gre", "v4") {
		kept = kept || (p.Method == "bp2_reverse" && p.Family == "v4" && p.Index == 201)
	}
	if !kept {
		t.Error("a plan dropped the picked v2 path (or its index)")
	}
	drop, _ := a.hsPathDiff(tun)
	for _, p := range drop {
		if p.Method == "bp2_reverse" {
			t.Error("Repair would drop the picked v2 path")
		}
	}
}
