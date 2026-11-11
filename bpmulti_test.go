package main

import (
	"strings"
	"testing"
)

func bpMultiConfs(t *testing.T, m *Method, tn *Tunnel) (string, string) {
	t.Helper()
	srv := &Server{ID: "ir", IPv4: "192.0.2.10", IPv6: "2001:db8::10"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.20", IPv6: "2001:db8::20", Role: "foreign"}
	ir, kh, err := buildPlans(m, tn, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := tunnelDir(tn) + "/tp-" + tn.ID + ".toml"
	if ir.Files[cfg].Mode != 0o600 || len(ir.Artifacts) != 1 || ir.Artifacts[0].Dest != "/usr/local/bin/backpack" {
		t.Fatalf("plan must reuse the panel's BackPack: %+v", ir.Artifacts)
	}
	return string(ir.Files[cfg].Content), string(kh.Files[cfg].Content)
}

func mustHave(t *testing.T, what, conf string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		// the panel appends its own probe port to the users' ports
		if !strings.Contains(conf, l+"\n") && !(strings.HasPrefix(l, "ports = ") && strings.Contains(conf, l)) {
			t.Errorf("%s config lacks %q:\n%s", what, l, conf)
		}
	}
}

func TestBackpackMultiBuild(t *testing.T) {
	tn := &Tunnel{ID: "t7", Name: "de", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "2053,8443=443", Index: 7,
		Options: map[string]map[string]string{"bp_multi": {"links": "16", "tunnel_port": "28301"}}}
	s, c := bpMultiConfs(t, methodBackpackMulti, tn)
	tok := tn.Secrets["bp-token"]
	if len(tok) < 16 {
		t.Fatalf("token %d chars", len(tok))
	}
	common := []string{`transport = "wsmux"`, `token = "` + tok + `"`, "nodelay = true", "keepalive_period = 75", "mux_version = 2",
		"mux_framesize = 32768", "mux_recievebuffer = 4194304", "mux_streambuffer = 65536", "mux_session = 1", "skip_optz = true",
		"sniffer = false", "web_port = 0", `log_level = "info"`}
	mustHave(t, "Iran", s, append(common, "[server]", `bind_addr = "0.0.0.0:28301"`, "heartbeat = 20", "mux_con = 8",
		"channel_size = 4096", "accept_udp = false", `ports = ["2053", "8443=443", "`)...)
	mustHave(t, "foreign", c, append(common, "[client]", `remote_addr = "192.0.2.10:28301"`, "connection_pool = 16", "dial_timeout = 10")...)
	// links is the client's pool, never the server's accept queue (a tiny queue drops users)
	if strings.Contains(c, "channel_size") || strings.Contains(s, "channel_size = 16") || strings.Contains(c, "kcp_") {
		t.Errorf("links in the wrong key:\n%s\n%s", s, c)
	}

	// IPv6: bind on [::], dial Iran's bracketed v6; defaults: 12 links, auto port
	tn6 := &Tunnel{ID: "t8", Name: "de6", ServerID: "ir", ForeignID: "kh", Family: "v6", Ports: "443", Index: 8,
		Options: map[string]map[string]string{"bp_multi": {"accept_udp": "true"}}}
	s6, c6 := bpMultiConfs(t, methodBackpackMulti, tn6)
	port := portOr("", deriveFor(tn6, &Server{ID: "ir"}, &Server{ID: "kh"}, Settings{}).BasePort)
	mustHave(t, "Iran v6", s6, `bind_addr = "[::]:`+port+`"`, "accept_udp = true", `ports = ["443", "`)
	mustHave(t, "foreign v6", c6, `remote_addr = "[2001:db8::10]:`+port+`"`, "connection_pool = 12")
}

func TestBackpackPckFECBuild(t *testing.T) {
	tn := &Tunnel{ID: "t9", Name: "nl", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "3525", Index: 9}
	s, c := bpMultiConfs(t, methodBackpackPckFEC, tn)
	kcp := []string{`transport = "pck"`, "kcp_datashards = 10", "kcp_parityshards = 4", "kcp_nodelay = 1", "kcp_interval = 10",
		"kcp_resend = 2", "kcp_nocongestion = 1", "kcp_acknodelay = true", "kcp_sndwnd = 1024", "kcp_rcvwnd = 1024", "kcp_mtu = 1350"}
	mustHave(t, "Iran", s, append(kcp, "mux_con = 7", `ports = ["3525", "`)...)
	mustHave(t, "foreign", c, append(kcp, "connection_pool = 3")...)

	// turbo: the same KCP/FEC, 6 links and 6 mux streams per link, no iface key
	tt := &Tunnel{ID: "t10", Name: "nl2", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "3534", Index: 10}
	st, ct := bpMultiConfs(t, methodBackpackPckTurbo, tt)
	mustHave(t, "turbo Iran", st, append(kcp, "mux_con = 6")...)
	mustHave(t, "turbo foreign", ct, append(kcp, "connection_pool = 6")...)
	if strings.Contains(st+ct, "iface") || methodByID["bp_pckturbo"] == nil || methodByID["bp_pckturbo"].Group != "BackPack" {
		t.Error("turbo: iface written or method not registered under BackPack")
	}

	tn.Family = "v6"
	if _, _, err := buildPlans(methodBackpackPckFEC, tn, &Server{ID: "ir", IPv6: "2001:db8::10"}, &Server{ID: "kh", IPv6: "2001:db8::20", Role: "foreign"}, Settings{}); err == nil {
		t.Error("pck over IPv6 must be refused")
	}
	if k, ok := reverseTCPPort(methodBackpackMulti, &Tunnel{}); !ok || k != "tunnel_port" {
		t.Error("wsmux multi-link dials Iran over TCP: the reverse preflight must check it")
	}
	if _, ok := reverseTCPPort(methodBackpackPckFEC, &Tunnel{}); ok {
		t.Error("pck is raw packets, not a TCP dial")
	}
}

func TestBackpackMultiLinksRange(t *testing.T) {
	for _, v := range []string{"0", "65", "x"} {
		if err := validateOptions(map[string]map[string]string{"bp_multi": {"links": v}}); err == nil {
			t.Errorf("links %q accepted", v)
		}
	}
	if err := validateOptions(map[string]map[string]string{"bp_multi": {"links": "12"}, "bp_pckfec": {"links": "3"}}); err != nil {
		t.Error(err)
	}
}
