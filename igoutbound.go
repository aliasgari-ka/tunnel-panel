package main

// Outbounds (the IG routing page's «خروجی‌ها», was «پروکسی‌ها»): besides an HTTP / SOCKS5 proxy, an
// exit can be an Xray config - a vless:// vmess:// trojan:// ss:// hysteria2:// share link, a
// subscription URL (many links, refreshable) or a raw Xray outbound JSON.
//
// The agent keeps them in the same file as the proxies (/etc/igproxy/proxies), so every route that
// takes "proxy" (Auto = the fastest healthy one) or "proxyN" takes them too:
//   xray <host> <port> <kind~remark~hash> <base64url of the outbound JSON>
// The 5th field holds the UUID / password: like a proxy password it never leaves the server once
// added (the list script prints only the first four fields) and is never logged.

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// igOut is one outbound parsed from what was pasted.
type igOut struct {
	Kind   string         `json:"kind"`   // vless-reality, vless-tls, vless, vmess, trojan, ss, hy2, xray, http, socks5
	Remark string         `json:"remark"` // the link's #name
	Host   string         `json:"host"`
	Port   string         `json:"port"`
	Net    string         `json:"net,omitempty"` // tcp / ws / grpc / xhttp / httpupgrade / kcp / hysteria
	ob     map[string]any // the Xray outbound (nil for a proxy)
	px     *igProxyIn     // a plain HTTP / SOCKS5 proxy
}

var (
	igUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	igSSMethods = map[string]bool{"aes-128-gcm": true, "aes-256-gcm": true, "chacha20-poly1305": true, "chacha20-ietf-poly1305": true,
		"xchacha20-poly1305": true, "xchacha20-ietf-poly1305": true, "2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
		"2022-blake3-chacha20-poly1305": true, "none": true, "plain": true}
)

// line is how the agent stores it.
func (o *igOut) line() (igProxyIn, error) {
	if o.px != nil {
		return *o.px, nil
	}
	b, err := json.Marshal(o.ob)
	if err != nil {
		return igProxyIn{}, err
	}
	if len(b) > 12000 {
		return igProxyIn{}, errors.New("the config is too big")
	}
	h := sha1.Sum(b)
	return igProxyIn{Type: "xray", Host: o.Host, Port: o.Port,
		User: o.Kind + "~" + igRemarkSafe(o.Remark) + "~" + hex.EncodeToString(h[:])[:6],
		Pass: base64.RawURLEncoding.EncodeToString(b)}, nil
}

// igRemarkSafe: the name as one word the agent's line can hold (letters of any script, digits, . _ -).
func igRemarkSafe(s string) string {
	var b strings.Builder
	n, dash := 0, false
	for _, r := range strings.TrimSpace(s) {
		if n >= 24 {
			break
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		} else {
			continue
		}
		n++
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "-"
	}
	return out
}

// igOutLabel splits a stored xray line's 4th field: kind, remark.
func igOutLabel(u string) (kind, remark string) {
	f := strings.SplitN(u, "~", 3)
	kind = f[0]
	if len(f) > 1 && f[1] != "-" {
		remark = f[1]
	}
	return
}

// igOutBadge: the type shown on the page.
func igOutBadge(kind string) string {
	switch kind {
	case "vless-reality":
		return "VLESS·Reality"
	case "vless-tls":
		return "VLESS·TLS"
	case "vless":
		return "VLESS"
	case "vmess", "vmess-tls":
		return "VMess"
	case "trojan":
		return "Trojan"
	case "ss":
		return "SS"
	case "hy2":
		return "Hysteria2"
	case "http":
		return "HTTP"
	case "socks5":
		return "SOCKS5"
	}
	return "Xray"
}

// ---- parse what was pasted

type igParseErr struct {
	Item string `json:"item"` // the start of the line (secrets cut off)
	Err  string `json:"err"`
}

// igOutHint: enough of a link to tell which one failed, without its UUID / password.
func igOutHint(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i > 0 && i < 12 {
		sch := s[:i+3]
		rest := s[i+3:]
		if j := strings.LastIndex(rest, "@"); j >= 0 {
			rest = "…@" + rest[j+1:]
		} else if len(rest) > 10 {
			rest = rest[:6] + "…"
		}
		if k := strings.IndexAny(rest, "?#/"); k > 0 {
			rest = rest[:k]
		}
		return sch + rest
	}
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}

// igSplitInput: one item per line (or whitespace); a JSON value is one item.
func igSplitInput(text string) []string {
	t := strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if t == "" {
		return nil
	}
	if t[0] == '{' || t[0] == '[' {
		return []string{t}
	}
	var out []string
	for _, l := range strings.Split(t, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			continue
		}
		// "http 1.2.3.4 8080 user pass" stays one item; several links on one line are split
		if strings.Contains(l, "://") && strings.Count(l, "://") > 1 {
			out = append(out, strings.Fields(l)...)
			continue
		}
		out = append(out, l)
	}
	return out
}

// igIsSubURL: an http(s) URL with a path or query is a subscription; http://host:port alone is an HTTP proxy.
func igIsSubURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	return (u.Path != "" && u.Path != "/") || u.RawQuery != "" || (u.Scheme == "https" && u.User == nil)
}

// igParseOne parses one pasted item (not a subscription URL).
func igParseOne(s string) ([]*igOut, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	if s[0] == '{' || s[0] == '[' {
		return igParseJSON(s)
	}
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "vless://"):
		o, err := igParseVless(s)
		return one(o, err)
	case strings.HasPrefix(low, "vmess://"):
		o, err := igParseVmess(s)
		return one(o, err)
	case strings.HasPrefix(low, "trojan://"):
		o, err := igParseTrojan(s)
		return one(o, err)
	case strings.HasPrefix(low, "ss://"):
		o, err := igParseSS(s)
		return one(o, err)
	case strings.HasPrefix(low, "hysteria2://"), strings.HasPrefix(low, "hy2://"):
		o, err := igParseHy2(s)
		return one(o, err)
	case strings.HasPrefix(low, "socks5://"), strings.HasPrefix(low, "socks://"), strings.HasPrefix(low, "socks5h://"), strings.HasPrefix(low, "http://"):
		u, err := url.Parse(s)
		if err != nil {
			return nil, errors.New("not a valid URL")
		}
		pw, _ := u.User.Password()
		t := "http"
		if strings.HasPrefix(u.Scheme, "socks") {
			t = "socks5"
		}
		p, err := igProxyNorm(t, u.Hostname(), u.Port(), u.User.Username(), pw)
		if err != nil {
			return nil, err
		}
		return []*igOut{{Kind: p.Type, Host: p.Host, Port: p.Port, px: &p}}, nil
	case strings.HasPrefix(low, "vmess+"), strings.HasPrefix(low, "tuic://"), strings.HasPrefix(low, "wireguard://"), strings.HasPrefix(low, "wg://"):
		return nil, errors.New("this kind of link is not supported (vless, vmess, trojan, ss, hysteria2, http, socks5)")
	}
	// "http 1.2.3.4 8080 [user] [pass]" / "1.2.3.4:8080" / "1.2.3.4:8080:user:pass"
	f := strings.Fields(s)
	t := "http"
	if len(f) > 0 && (strings.EqualFold(f[0], "http") || strings.HasPrefix(strings.ToLower(f[0]), "socks")) {
		t, f = f[0], f[1:]
	}
	if len(f) == 1 && strings.Count(f[0], ":") >= 1 && !strings.Contains(f[0], "[") {
		c := strings.Split(f[0], ":")
		if len(c) == 2 || len(c) == 4 {
			f = c
		}
	}
	if len(f) < 2 {
		return nil, errors.New("not a link, a proxy or an Xray JSON")
	}
	g := func(i int) string {
		if i < len(f) {
			return f[i]
		}
		return ""
	}
	p, err := igProxyNorm(t, g(0), g(1), g(2), g(3))
	if err != nil {
		return nil, err
	}
	return []*igOut{{Kind: p.Type, Host: p.Host, Port: p.Port, px: &p}}, nil
}

func one(o *igOut, err error) ([]*igOut, error) {
	if err != nil {
		return nil, err
	}
	return []*igOut{o}, nil
}

func igHostPort(h, p string) (string, string, error) {
	h = strings.TrimSpace(igDigits(h))
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		if ip.To4() != nil {
			h = ip.To4().String()
		} else {
			h = "[" + ip.String() + "]"
		}
	} else if h == "" || len(h) > 253 || !igHostName.MatchString(h) {
		return "", "", errors.New("bad server address")
	}
	n, err := strconv.Atoi(strings.TrimSpace(igDigits(p)))
	if err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("bad port")
	}
	return h, strconv.Itoa(n), nil
}

// xaddr: the address the way Xray takes it (no brackets).
func xaddr(h string) string { return strings.Trim(h, "[]") }

func igFrag(u *url.URL) string {
	r, err := url.PathUnescape(u.Fragment)
	if err != nil {
		r = u.Fragment
	}
	return r
}

func qget(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

// igStream builds streamSettings from share-link parameters (the v2rayN / Xray convention).
func igStream(q url.Values, security, host string) (map[string]any, string, error) {
	netw := strings.ToLower(qget(q, "type", "net"))
	switch netw {
	case "", "tcp", "raw":
		netw = "tcp"
	case "splithttp":
		netw = "xhttp"
	case "ws", "grpc", "xhttp", "httpupgrade", "kcp", "mkcp":
		if netw == "mkcp" {
			netw = "kcp"
		}
	case "h2", "http":
		return nil, "", errors.New("the h2/http transport was removed from Xray - use xhttp")
	case "quic":
		return nil, "", errors.New("the quic transport was removed from Xray")
	default:
		return nil, "", fmt.Errorf("unknown transport %q", netw)
	}
	st := map[string]any{"network": netw}
	path, hh := qget(q, "path"), qget(q, "host")
	switch netw {
	case "tcp":
		if strings.EqualFold(qget(q, "headerType"), "http") {
			req := map[string]any{}
			if path != "" {
				req["path"] = strings.Split(path, ",")
			}
			if hh != "" {
				req["headers"] = map[string]any{"Host": strings.Split(hh, ",")}
			}
			st["tcpSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws":
		w := map[string]any{"path": igOr(path, "/")}
		if hh != "" {
			w["host"] = hh
		}
		st["wsSettings"] = w
	case "httpupgrade":
		w := map[string]any{"path": igOr(path, "/")}
		if hh != "" {
			w["host"] = hh
		}
		st["httpupgradeSettings"] = w
	case "grpc":
		g := map[string]any{"serviceName": qget(q, "serviceName", "path")}
		if strings.EqualFold(qget(q, "mode"), "multi") {
			g["multiMode"] = true
		}
		if a := qget(q, "authority"); a != "" {
			g["authority"] = a
		}
		st["grpcSettings"] = g
	case "xhttp":
		x := map[string]any{"path": igOr(path, "/")}
		if hh != "" {
			x["host"] = hh
		}
		if m := qget(q, "mode"); m != "" {
			x["mode"] = m
		}
		if e := qget(q, "extra"); e != "" {
			var ex map[string]any
			if json.Unmarshal([]byte(e), &ex) != nil {
				return nil, "", errors.New("xhttp extra is not JSON")
			}
			x["extra"] = ex
		}
		st["xhttpSettings"] = x
	case "kcp":
		k := map[string]any{}
		if s := qget(q, "seed"); s != "" {
			k["seed"] = s
		}
		if t := qget(q, "headerType"); t != "" && t != "none" {
			k["header"] = map[string]any{"type": t}
		}
		st["kcpSettings"] = k
	}
	sni := qget(q, "sni", "peer", "serverName")
	fp := qget(q, "fp", "fingerprint")
	switch strings.ToLower(security) {
	case "", "none":
	case "tls":
		t := map[string]any{}
		if sni == "" && hh != "" && netw != "tcp" {
			sni = strings.Split(hh, ",")[0]
		}
		if sni != "" {
			t["serverName"] = sni
		} else if net.ParseIP(xaddr(host)) == nil {
			t["serverName"] = host
		}
		if fp != "" {
			t["fingerprint"] = fp
		}
		if a := qget(q, "alpn"); a != "" {
			t["alpn"] = strings.Split(a, ",")
		}
		if v := qget(q, "allowInsecure", "insecure"); v == "1" || strings.EqualFold(v, "true") {
			t["allowInsecure"] = true
		}
		if v := qget(q, "pcs", "pinnedPeerCertificateChainSha256"); v != "" {
			t["pinnedPeerCertificateChainSha256"] = strings.Split(v, ",")
		}
		if e := qget(q, "ech", "echConfigList"); e != "" {
			t["echConfigList"] = e
		}
		st["security"] = "tls"
		st["tlsSettings"] = t
	case "reality":
		pbk := qget(q, "pbk", "publicKey", "password")
		if pbk == "" {
			return nil, "", errors.New("REALITY needs the public key (pbk)")
		}
		if sni == "" {
			return nil, "", errors.New("REALITY needs the server name (sni)")
		}
		r := map[string]any{"serverName": sni, "publicKey": pbk, "fingerprint": igOr(fp, "chrome")}
		if v := qget(q, "sid", "shortId"); v != "" {
			r["shortId"] = v
		}
		if v := qget(q, "spx", "spiderX"); v != "" {
			r["spiderX"] = v
		}
		if v := qget(q, "pqv", "mldsa65Verify"); v != "" {
			r["mldsa65Verify"] = v
		}
		st["security"] = "reality"
		st["realitySettings"] = r
	default:
		return nil, "", fmt.Errorf("unknown security %q", security)
	}
	return st, netw, nil
}

func igOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func igParseVless(s string) (*igOut, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("not a valid vless:// link")
	}
	id := u.User.Username()
	if !igUUID.MatchString(id) && (len(id) < 1 || len(id) > 30) {
		return nil, errors.New("the user id is not a UUID")
	}
	h, p, err := igHostPort(u.Hostname(), u.Port())
	if err != nil {
		return nil, err
	}
	q := u.Query()
	sec := strings.ToLower(qget(q, "security"))
	st, netw, err := igStream(q, sec, h)
	if err != nil {
		return nil, err
	}
	usr := map[string]any{"id": id, "encryption": igOr(qget(q, "encryption"), "none")}
	if f := qget(q, "flow"); f != "" {
		if netw != "tcp" || (sec != "tls" && sec != "reality") {
			return nil, errors.New("flow (xtls-rprx-vision) works only on tcp with TLS or REALITY")
		}
		usr["flow"] = f
	}
	kind := "vless"
	if sec == "reality" {
		kind = "vless-reality"
	} else if sec == "tls" {
		kind = "vless-tls"
	}
	ob := map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": xaddr(h), "port": atoiOr(p), "users": []any{usr}}}}, "streamSettings": st}
	return &igOut{Kind: kind, Remark: igFrag(u), Host: h, Port: p, Net: netw, ob: ob}, nil
}

func igB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

func igParseVmess(s string) (*igOut, error) {
	b, err := igB64(s[len("vmess://"):])
	if err != nil {
		return nil, errors.New("vmess:// link: the part after vmess:// is not base64 JSON")
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return nil, errors.New("vmess:// link: not JSON inside")
	}
	g := func(k string) string {
		switch x := v[k].(type) {
		case string:
			return strings.TrimSpace(x)
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		}
		return ""
	}
	id := g("id")
	if !igUUID.MatchString(id) {
		return nil, errors.New("vmess: the id is not a UUID")
	}
	h, p, err := igHostPort(g("add"), g("port"))
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("type", igOr(g("net"), "tcp"))
	q.Set("headerType", g("type"))
	for _, k := range []string{"host", "path", "sni", "alpn", "fp"} {
		q.Set(k, g(k))
	}
	if q.Get("type") == "grpc" {
		q.Set("serviceName", g("path"))
		if g("type") == "multi" {
			q.Set("mode", "multi")
		}
		q.Set("headerType", "")
	}
	sec := ""
	if strings.EqualFold(g("tls"), "tls") {
		sec = "tls"
	}
	st, netw, err := igStream(q, sec, h)
	if err != nil {
		return nil, err
	}
	aid, _ := strconv.Atoi(igOr(g("aid"), "0"))
	ob := map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{"address": xaddr(h), "port": atoiOr(p),
		"users": []any{map[string]any{"id": id, "alterId": aid, "security": igOr(g("scy"), "auto")}}}}}, "streamSettings": st}
	return &igOut{Kind: "vmess", Remark: g("ps"), Host: h, Port: p, Net: netw, ob: ob}, nil
}

func igParseTrojan(s string) (*igOut, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("not a valid trojan:// link")
	}
	pw := u.User.Username()
	if pw == "" {
		return nil, errors.New("trojan: the password is missing")
	}
	h, p, err := igHostPort(u.Hostname(), u.Port())
	if err != nil {
		return nil, err
	}
	q := u.Query()
	sec := igOr(strings.ToLower(qget(q, "security")), "tls")
	st, netw, err := igStream(q, sec, h)
	if err != nil {
		return nil, err
	}
	srv := map[string]any{"address": xaddr(h), "port": atoiOr(p), "password": pw}
	if f := qget(q, "flow"); f != "" {
		srv["flow"] = f
	}
	ob := map[string]any{"protocol": "trojan", "settings": map[string]any{"servers": []any{srv}}, "streamSettings": st}
	return &igOut{Kind: "trojan", Remark: igFrag(u), Host: h, Port: p, Net: netw, ob: ob}, nil
}

func igParseSS(s string) (*igOut, error) {
	body := s[len("ss://"):]
	remark := ""
	if i := strings.Index(body, "#"); i >= 0 {
		remark, _ = url.PathUnescape(body[i+1:])
		body = body[:i]
	}
	if i := strings.Index(body, "?"); i >= 0 {
		q, _ := url.ParseQuery(body[i+1:])
		if q.Get("plugin") != "" {
			return nil, errors.New("ss: plugins (obfs / v2ray-plugin) are not supported")
		}
		body = body[:i]
	}
	body = strings.TrimSuffix(body, "/")
	var userinfo, hostport string
	if i := strings.LastIndex(body, "@"); i >= 0 {
		userinfo, hostport = body[:i], body[i+1:]
		if b, err := igB64(userinfo); err == nil && strings.Contains(string(b), ":") {
			userinfo = string(b)
		} else if d, err := url.PathUnescape(userinfo); err == nil {
			userinfo = d
		}
	} else { // legacy: base64(method:password@host:port)
		b, err := igB64(body)
		if err != nil {
			return nil, errors.New("ss:// link: cannot read it")
		}
		t := string(b)
		i := strings.LastIndex(t, "@")
		if i < 0 {
			return nil, errors.New("ss:// link: no server in it")
		}
		userinfo, hostport = t[:i], t[i+1:]
	}
	m, pw, ok := strings.Cut(userinfo, ":")
	m = strings.ToLower(strings.TrimSpace(m))
	if !ok || pw == "" {
		return nil, errors.New("ss: method:password is missing")
	}
	if !igSSMethods[m] {
		return nil, fmt.Errorf("ss: the method %q is not supported by Xray", m)
	}
	hs, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, errors.New("ss: bad server address")
	}
	h, p, err := igHostPort(hs, ps)
	if err != nil {
		return nil, err
	}
	ob := map[string]any{"protocol": "shadowsocks", "settings": map[string]any{"servers": []any{map[string]any{"address": xaddr(h), "port": atoiOr(p), "method": m, "password": pw}}},
		"streamSettings": map[string]any{"network": "tcp"}}
	return &igOut{Kind: "ss", Remark: remark, Host: h, Port: p, Net: "tcp", ob: ob}, nil
}

func igParseHy2(s string) (*igOut, error) {
	if strings.HasPrefix(strings.ToLower(s), "hy2://") {
		s = "hysteria2://" + s[len("hy2://"):]
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("not a valid hysteria2:// link")
	}
	auth := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		auth += ":" + pw
	}
	port := u.Port()
	if strings.ContainsAny(port, ",-") {
		return nil, errors.New("hysteria2: port hopping (a port range) is not supported - one port only")
	}
	h, p, err := igHostPort(u.Hostname(), igOr(port, "443"))
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if qget(q, "obfs") != "" {
		return nil, errors.New("hysteria2: obfs (salamander) is not supported by the router's Xray")
	}
	t := map[string]any{"alpn": []any{"h3"}}
	if sni := qget(q, "sni", "peer"); sni != "" {
		t["serverName"] = sni
	} else if net.ParseIP(xaddr(h)) == nil {
		t["serverName"] = h
	}
	if v := qget(q, "insecure", "allowInsecure"); v == "1" || strings.EqualFold(v, "true") {
		t["allowInsecure"] = true
	}
	hs := map[string]any{"version": 2}
	if auth != "" {
		hs["auth"] = auth
	}
	ob := map[string]any{"protocol": "hysteria", "settings": map[string]any{"version": 2, "address": xaddr(h), "port": atoiOr(p)},
		"streamSettings": map[string]any{"network": "hysteria", "hysteriaSettings": hs, "security": "tls", "tlsSettings": t}}
	return &igOut{Kind: "hy2", Remark: igFrag(u), Host: h, Port: p, Net: "hysteria", ob: ob}, nil
}

// igParseJSON: one Xray outbound, a list of them, or a whole client config (its proxy outbounds).
func igParseJSON(s string) ([]*igOut, error) {
	var v any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("JSON: %v", err)
	}
	var list []any
	switch x := v.(type) {
	case []any:
		list = x
	case map[string]any:
		if obs, ok := x["outbounds"].([]any); ok {
			list = obs
		} else if x["outbound"] != nil {
			list = []any{x["outbound"]}
		} else {
			list = []any{x}
		}
	}
	var out []*igOut
	var errs []string
	for _, it := range list {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		o, err := igFromOutbound(m)
		if err != nil {
			if err != errSkip {
				errs = append(errs, err.Error())
			}
			continue
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		if len(errs) > 0 {
			return nil, errors.New(errs[0])
		}
		return nil, errors.New("JSON: no proxy outbound in it (vless, vmess, trojan, shadowsocks, hysteria, socks, http)")
	}
	return out, nil
}

var errSkip = errors.New("skip")

func igFromOutbound(m map[string]any) (*igOut, error) {
	proto, _ := m["protocol"].(string)
	proto = strings.ToLower(proto)
	switch proto {
	case "freedom", "blackhole", "dns", "loopback", "":
		return nil, errSkip
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria", "socks", "http", "wireguard":
	default:
		return nil, fmt.Errorf("JSON: protocol %q is not supported", proto)
	}
	if _, ok := m["proxySettings"]; ok {
		return nil, errors.New("JSON: proxySettings (a chain through another outbound) is not supported")
	}
	ob := map[string]any{}
	for k, v := range m {
		switch k {
		case "tag", "sendThrough", "proxySettings":
		default:
			ob[k] = v
		}
	}
	st, _ := m["settings"].(map[string]any)
	host, port := "", ""
	pick := func(x map[string]any) {
		host, _ = x["address"].(string)
		port = fmt.Sprint(x["port"])
	}
	if st != nil {
		if a, ok := st["vnext"].([]any); ok && len(a) > 0 {
			if x, ok := a[0].(map[string]any); ok {
				pick(x)
			}
		} else if a, ok := st["servers"].([]any); ok && len(a) > 0 {
			if x, ok := a[0].(map[string]any); ok {
				pick(x)
			}
		} else if a, ok := st["peers"].([]any); ok && len(a) > 0 {
			if x, ok := a[0].(map[string]any); ok {
				if ep, _ := x["endpoint"].(string); ep != "" {
					host, port, _ = net.SplitHostPort(ep)
				}
			}
		} else if _, ok := st["address"]; ok {
			pick(st)
		}
	}
	h, p, err := igHostPort(host, port)
	if err != nil {
		return nil, fmt.Errorf("JSON (%s): %v", proto, err)
	}
	kind := map[string]string{"vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "ss", "hysteria": "hy2", "socks": "xray", "http": "xray", "wireguard": "xray"}[proto]
	ss, _ := m["streamSettings"].(map[string]any)
	netw := "tcp"
	if ss != nil {
		if n, _ := ss["network"].(string); n != "" {
			netw = n
		}
		if proto == "vless" {
			switch ss["security"] {
			case "reality":
				kind = "vless-reality"
			case "tls":
				kind = "vless-tls"
			}
		}
	}
	remark, _ := m["tag"].(string)
	return &igOut{Kind: kind, Remark: remark, Host: h, Port: p, Net: netw, ob: ob}, nil
}

// ---- subscriptions

// igFetchSub downloads a subscription (base64 or a plain list of links; Clash YAML is not read).
var igSubClient = &http.Client{Timeout: 25 * time.Second}

func igFetchSub(ctx context.Context, raw string) ([]string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("not an http(s) URL")
	}
	if igBlockedHost(u.Hostname()) {
		return nil, errors.New("that address is not allowed (local / private)")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
	req.Header.Set("User-Agent", "v2rayN/7.0")
	resp, err := igSubClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download failed: %v", igScrubErr(err, raw))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("the subscription answered http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, errors.New("download cut off")
	}
	return igSubLinks(b)
}

// igScrubErr: a Go URL error repeats the whole URL (its token): name the host only.
func igScrubErr(err error, raw string) string {
	s := err.Error()
	if u, e := url.Parse(raw); e == nil {
		s = strings.ReplaceAll(s, raw, u.Scheme+"://"+u.Host+"/…")
	}
	return s
}

func igSubLinks(b []byte) ([]string, error) {
	t := strings.TrimSpace(string(b))
	if !strings.Contains(t, "://") {
		if d, err := igB64(t); err == nil {
			t = string(d)
		}
	}
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		return []string{t}, nil
	}
	var out []string
	for _, l := range strings.Split(t, "\n") {
		l = strings.TrimSpace(l)
		if strings.Contains(l, "://") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		if strings.Contains(t, "proxies:") {
			return nil, errors.New("a Clash (YAML) subscription - ask for the v2ray / base64 format")
		}
		return nil, errors.New("no links in the subscription")
	}
	return out, nil
}

// igBlockedHost: the panel never fetches its own network for someone (SSRF): loopback, private, link-local.
func igBlockedHost(h string) bool {
	ips := []net.IP{}
	if ip := net.ParseIP(h); ip != nil {
		ips = append(ips, ip)
	} else {
		if strings.EqualFold(h, "localhost") || strings.HasSuffix(strings.ToLower(h), ".localhost") {
			return true
		}
		addrs, err := net.LookupIP(h)
		if err != nil {
			return false // the download fails by itself
		}
		ips = addrs
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return true
		}
	}
	return false
}

// igParseInput: everything pasted -> outbounds + per-item errors; subscription URLs are fetched.
// subs = the subscription URLs that were in it.
func igParseInput(ctx context.Context, text string) (outs []*igOut, errs []igParseErr, subs []string) {
	seen := map[string]bool{}
	add := func(o *igOut) {
		l, err := o.line()
		if err != nil {
			errs = append(errs, igParseErr{Item: o.Host, Err: err.Error()})
			return
		}
		k := igProxyKey(l.Type, l.Host, l.Port, l.User)
		if !seen[k] {
			seen[k] = true
			outs = append(outs, o)
		}
	}
	for _, it := range igSplitInput(text) {
		if igIsSubURL(it) {
			subs = append(subs, it)
			links, err := igFetchSub(ctx, it)
			if err != nil {
				errs = append(errs, igParseErr{Item: igSubHint(it), Err: err.Error()})
				continue
			}
			for _, l := range links {
				os, err := igParseOne(l)
				if err != nil {
					errs = append(errs, igParseErr{Item: igOutHint(l), Err: err.Error()})
					continue
				}
				for _, o := range os {
					add(o)
				}
			}
			continue
		}
		os, err := igParseOne(it)
		if err != nil {
			errs = append(errs, igParseErr{Item: igOutHint(it), Err: err.Error()})
			continue
		}
		for _, o := range os {
			add(o)
		}
	}
	return
}

// igSubHint: a subscription URL without its token (host + first path part).
func igSubHint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "subscription"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// igOutSummary is what the page shows before adding (no secrets).
type igOutSummary struct {
	Kind   string `json:"kind"`
	Badge  string `json:"badge"`
	Remark string `json:"remark,omitempty"`
	Host   string `json:"host"`
	Port   string `json:"port"`
	Net    string `json:"net,omitempty"`
}

func igOutSummaries(outs []*igOut) []igOutSummary {
	r := make([]igOutSummary, 0, len(outs))
	for _, o := range outs {
		r = append(r, igOutSummary{Kind: o.Kind, Badge: igOutBadge(o.Kind), Remark: o.Remark, Host: o.Host, Port: o.Port, Net: o.Net})
	}
	return r
}
