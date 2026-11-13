package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// test-only values (not real servers or keys)
const (
	tUUID = "11111111-2222-4333-8444-555555555555"
	tPBK  = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
)

func outJSON(t *testing.T, o *igOut) map[string]any {
	t.Helper()
	b, _ := json.Marshal(o.ob)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func TestIgParseVlessReality(t *testing.T) {
	l := "vless://" + tUUID + "@203.0.113.7:443?security=reality&encryption=none&pbk=" + tPBK + "&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com&sid=6ba85179e30d4fc2#DE%20Frankfurt%201"
	os, err := igParseOne(l)
	if err != nil {
		t.Fatal(err)
	}
	o := os[0]
	if o.Kind != "vless-reality" || o.Host != "203.0.113.7" || o.Port != "443" || o.Remark != "DE Frankfurt 1" {
		t.Fatalf("%+v", o)
	}
	m := outJSON(t, o)
	ss := m["streamSettings"].(map[string]any)
	rs := ss["realitySettings"].(map[string]any)
	if ss["security"] != "reality" || rs["publicKey"] != tPBK || rs["serverName"] != "www.microsoft.com" || rs["shortId"] != "6ba85179e30d4fc2" {
		t.Fatalf("%v", ss)
	}
	u := m["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if u["flow"] != "xtls-rprx-vision" || u["id"] != tUUID {
		t.Fatal(u)
	}
	p, err := o.line()
	if err != nil || p.Type != "xray" || !strings.HasPrefix(p.User, "vless-reality~DE-Frankfurt-1~") || strings.ContainsAny(p.Pass, " \t\n") {
		t.Fatalf("%+v %v", p, err)
	}
	// the stored line has 5 space-separated fields and the secret only in the 5th
	f := strings.Fields(p.line())
	if len(f) != 5 || strings.Contains(strings.Join(f[:4], " "), tUUID) {
		t.Fatal(f[:4])
	}
	b, _ := base64.RawURLEncoding.DecodeString(f[4])
	if !strings.Contains(string(b), tUUID) {
		t.Fatal("secret not in the 5th field")
	}
}

func TestIgParseVariants(t *testing.T) {
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "vm 1", "add": "vm.example.com", "port": "8443", "id": tUUID, "aid": "0", "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/ws", "tls": "tls", "sni": "cdn.example.com"})
	ss := base64.URLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pass123"))
	cases := []struct{ in, kind, net string }{
		{"vless://" + tUUID + "@vl.example.com:443?security=tls&type=ws&path=%2Fabc&host=cdn.example.com&sni=cdn.example.com#ws", "vless-tls", "ws"},
		{"vless://" + tUUID + "@vl.example.com:443?security=tls&type=grpc&serviceName=gs&mode=multi#g", "vless-tls", "grpc"},
		{"vless://" + tUUID + "@vl.example.com:443?security=reality&type=xhttp&path=%2Fx&mode=auto&pbk=" + tPBK + "&sni=a.com#x", "vless-reality", "xhttp"},
		{"vless://" + tUUID + "@[2001:db8::5]:443?security=none&type=httpupgrade&path=%2Fu#v6", "vless", "httpupgrade"},
		{"vmess://" + base64.StdEncoding.EncodeToString(vm), "vmess", "ws"},
		{"trojan://secretpw@tr.example.com:443?sni=tr.example.com&type=tcp#tr", "trojan", "tcp"},
		{"ss://" + ss + "@198.51.100.4:8388#ss1", "ss", "tcp"},
		{"ss://2022-blake3-aes-128-gcm:" + "YWJjZGVmZ2hpamtsbW5vcA%3D%3D" + "@198.51.100.4:8388#ss2022", "ss", "tcp"},
		{"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw@198.51.100.9:443")) + "#legacy", "ss", "tcp"},
		{"hysteria2://authpw@hy.example.com:443?sni=hy.example.com&insecure=1#hy", "hy2", "hysteria"},
		{"hy2://authpw@203.0.113.9:8443/?sni=x.com", "hy2", "hysteria"},
		{"socks5://u1:p1@203.0.113.1:1080", "socks5", ""},
		{"http 203.0.113.2 3128 user pw", "http", ""},
		{"203.0.113.3:8080", "http", ""},
	}
	for _, c := range cases {
		os, err := igParseOne(c.in)
		if err != nil {
			t.Fatalf("%s: %v", igOutHint(c.in), err)
		}
		if os[0].Kind != c.kind || os[0].Net != c.net {
			t.Fatalf("%s: kind %s net %s", igOutHint(c.in), os[0].Kind, os[0].Net)
		}
		if _, err := os[0].line(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIgParseErrors(t *testing.T) {
	bad := map[string]string{
		"vless://notauuid-but-way-too-long-to-be-a-short-id@a.com:443?security=none": "UUID",
		"vless://" + tUUID + "@a.com:443?security=reality&sni=a.com":                 "pbk",
		"vless://" + tUUID + "@a.com:99999?security=none":                            "port",
		"vless://" + tUUID + "@a.com:443?type=h2&security=tls":                       "xhttp",
		"vless://" + tUUID + "@a.com:443?type=ws&security=none&flow=xtls-rprx-vision": "flow",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("rc4-md5:x")) + "@a.com:1":  "method",
		"ss://YWVzLTI1Ni1nY206eA@a.com:1?plugin=obfs-local":                          "plugin",
		"hysteria2://x@a.com:443?obfs=salamander&obfs-password=y":                    "obfs",
		"hysteria2://x@a.com:20000-30000":                                            "",
		"tuic://x@a.com:1":                                                           "not supported",
		"hello":                                                                      "not a link",
	}
	for in, want := range bad {
		_, err := igParseOne(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%q: %v", in, err)
		}
		if strings.Contains(err.Error(), tUUID) {
			t.Fatal("error repeats the id")
		}
	}
	if h := igOutHint("vless://" + tUUID + "@a.com:443?x=1#n"); strings.Contains(h, tUUID) || h != "vless://…@a.com:443" {
		t.Fatal(h)
	}
}

func TestIgParseJSON(t *testing.T) {
	cfg := `{"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"203.0.113.8","port":443,"users":[{"id":"` + tUUID + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"a.com","publicKey":"` + tPBK + `"}}},{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}`
	os, err := igParseOne(cfg)
	if err != nil || len(os) != 1 || os[0].Kind != "vless-reality" || os[0].Host != "203.0.113.8" {
		t.Fatalf("%v %v", os, err)
	}
	if _, ok := os[0].ob["tag"]; ok {
		t.Fatal("tag kept")
	}
	if _, err := igParseOne(`{"protocol":"freedom"}`); err == nil {
		t.Fatal("freedom accepted")
	}
	if _, err := igParseOne(`{"protocol":"vless","settings":{}}`); err == nil {
		t.Fatal("no address accepted")
	}
}

func TestIgSplitAndSub(t *testing.T) {
	links := "vless://" + tUUID + "@a.example.com:443?security=none#1\r\ntrojan://pw@b.example.com:443#2\n\nss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:x")) + "@198.51.100.1:1#3"
	if got := igSplitInput(links); len(got) != 3 {
		t.Fatal(got)
	}
	if got := igSplitInput("vless://" + tUUID + "@a.com:1#a vless://" + tUUID + "@b.com:1#b"); len(got) != 2 {
		t.Fatal(got)
	}
	for in, want := range map[string]bool{"https://sub.example.com/api/v1/client/subscribe?token=abc": true, "http://1.2.3.4:8080": false, "https://sub.example.com": true, "http://u:p@1.2.3.4:3128": false} {
		if igIsSubURL(in) != want {
			t.Fatal(in)
		}
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(links))
	got, err := igSubLinks([]byte(b64))
	if err != nil || len(got) != 3 {
		t.Fatal(got, err)
	}
	if _, err := igSubLinks([]byte("proxies:\n - name: a")); err == nil || !strings.Contains(err.Error(), "Clash") {
		t.Fatal(err)
	}
	// local / private addresses are never fetched
	for _, h := range []string{"127.0.0.1", "localhost", "10.0.0.5", "169.254.169.254", "::1"} {
		if !igBlockedHost(h) {
			t.Fatal(h)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(b64)) }))
	defer srv.Close()
	if _, err := igFetchSub(context.Background(), srv.URL+"/sub?token=SECRET"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("local subscription fetched or token in the error:", err)
	}
	if h := igSubHint("https://sub.example.com/api/sub?token=SECRET"); strings.Contains(h, "SECRET") {
		t.Fatal(h)
	}
}

func TestIgRemarkAndLabel(t *testing.T) {
	if r := igRemarkSafe("🇩🇪 آلمان | Fast #1 "); strings.ContainsAny(r, " ~:|#") || r == "" {
		t.Fatal(r)
	}
	if r := igRemarkSafe(""); r != "-" {
		t.Fatal(r)
	}
	k, r := igOutLabel("vless-reality~DE-1~abc123")
	if k != "vless-reality" || r != "DE-1" || igOutBadge(k) != "VLESS·Reality" {
		t.Fatal(k, r)
	}
}

func TestIgAddManyParse(t *testing.T) {
	m := igAddManyLine.FindStringSubmatch("  [2] OK - exit IP 203.0.113.7 (DE)  420ms -> proxy 6")
	if m == nil || m[1] != "2" || m[2] != "203.0.113.7" || m[3] != "DE" || m[4] != "420" || m[5] != "6" {
		t.Fatal(m)
	}
	m = igAddManyLine.FindStringSubmatch("  [1] already in the list as proxy 3")
	if m == nil || m[6] != "3" {
		t.Fatal(m)
	}
	m = igAddManyLine.FindStringSubmatch("  [3] !! no connection through this config")
	if m == nil || m[7] == "" {
		t.Fatal(m)
	}
}

// TestIgOutDump writes sample agent lines for the agent's config generator (IGOUT_DUMP=<file>).
func TestIgOutDump(t *testing.T) {
	f := os.Getenv("IGOUT_DUMP")
	if f == "" {
		t.Skip("IGOUT_DUMP not set")
	}
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "vm", "add": "203.0.113.20", "port": "8443", "id": tUUID, "aid": "0", "net": "ws", "host": "c.example.com", "path": "/ws", "tls": "tls"})
	in := []string{
		"http 203.0.113.1 3128",
		"vless://" + tUUID + "@203.0.113.21:443?security=reality&pbk=" + tPBK + "&sni=www.microsoft.com&sid=6ba8&fp=chrome&flow=xtls-rprx-vision#r",
		"vless://" + tUUID + "@203.0.113.22:443?security=tls&type=xhttp&path=%2Fx&sni=a.example.com#xh",
		"vless://" + tUUID + "@203.0.113.23:443?security=tls&type=grpc&serviceName=g&sni=a.example.com#g",
		"vmess://" + base64.StdEncoding.EncodeToString(vm),
		"trojan://pw@203.0.113.24:443?sni=t.example.com&type=ws&path=%2Ft#t",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw")) + "@203.0.113.25:8388#s",
		"ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@203.0.113.26:8388#s2",
		"hysteria2://pw@203.0.113.27:443?sni=h.example.com#h",
		"vless://" + tUUID + "@203.0.113.28:443?security=none&type=httpupgrade&path=%2Fu#hu",
		"vless://" + tUUID + "@203.0.113.29:443?security=tls&type=ws&path=%2Fw&host=w.example.com#w",
	}
	var out []string
	for _, l := range in {
		os, err := igParseOne(l)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := os[0].line()
		out = append(out, p.line())
	}
	if err := writeFileStr(f, strings.Join(out, "\n")+"\n"); err != nil {
		t.Fatal(err)
	}
}

func writeFileStr(f, s string) error { return os.WriteFile(f, []byte(s), 0600) }
