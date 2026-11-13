#!/usr/bin/env python3
"""Outbounds for the igproxy agent: Xray configs (vless / vmess / trojan / ss / hysteria2 / any outbound
JSON) next to the HTTP / SOCKS5 proxies, in the same file and with the same numbers.

  /etc/igproxy/proxies line:  xray <host> <port> <kind~remark~hash> <base64url outbound JSON>

- the router gets outbound proxyN from the JSON (tag + sockopt.mark set by the agent), so "proxy"
  (the leastPing pool, i.e. Auto) and "proxyN" routes take them like any proxy
- every Xray line also gets a local test socket 127.0.0.1:XOUT_TB+N -> pargs() hands curl that, so
  every existing check (Instagram, music, Google, country, users' path) works unchanged
- proxy add tests an Xray line in a temporary Xray (the WARP test port, under its lock) first
- proxy addmany: many lines on stdin, each tested, ONE router reload at the end
- secrets: the 5th field is never printed (proxy list prints fields 1-4) nor logged; Xray's own
  error lines are scrubbed of UUIDs / long tokens

Idempotent: run it on whatever /root/igproxy.sh is (marker "XOUT_TB=").
usage: patch_xout.py <in> <out>
"""
import sys

src = open(sys.argv[1], encoding="utf-8").read()
if "XOUT_TB=" in src:
    open(sys.argv[2], "w", encoding="utf-8", newline="\n").write(src)
    print("already patched")
    sys.exit(0)


def rep(old, new, count=1):
    global src
    n = src.count(old)
    if n != count:
        sys.exit(f"anchor found {n}x (want {count}): {old[:80]!r}")
    src = src.replace(old, new)


# 1. test sockets of the Xray outbounds
rep("WARP_TRY_PORT=12399           # temporary Xray to test a WARP before it goes live\n",
    "WARP_TRY_PORT=12399           # temporary Xray to test a WARP before it goes live\n"
    "XOUT_TB=12300                 # 127.0.0.1:12301.. = proxy line 1.. when it is an Xray outbound (tests)\n")

# 2. keep 12301-12344 out of the ephemeral ports too (like 12345-12399)
old = """ExecStartPre=-/bin/sh -c 'r=\\$\\$(sysctl -n net.ipv4.ip_local_reserved_ports); case ",\\$\\$r," in *,$PORT_LOCAL-$WARP_TRY_PORT,*) ;; *) sysctl -qw net.ipv4.ip_local_reserved_ports="\\$\\${r:+\\$\\$r,}$PORT_LOCAL-$WARP_TRY_PORT";; esac'
"""
new = old + """ExecStartPre=-/bin/sh -c 'r=\\$\\$(sysctl -n net.ipv4.ip_local_reserved_ports); case ",\\$\\$r," in *,$((XOUT_TB+1))-$((PORT_LOCAL-1)),*|*,$((XOUT_TB+1))-$WARP_TRY_PORT,*) ;; *) sysctl -qw net.ipv4.ip_local_reserved_ports="\\$\\${r:+\\$\\$r,}$((XOUT_TB+1))-$((PORT_LOCAL-1))";; esac'
"""
rep(old, new)

# 3. pargs: an Xray line is reached through its test socket
rep("""pargs(){ # pargs "<type host port user pass>" -> PA=( curl args for this proxy )
  local t h p u pw s=socks5h; read -r t h p u pw <<<"$1"; [ "$t" = http ] && s=http; [ "$pw" = - ] && pw=""
""", """pargs(){ # pargs "<type host port user pass>" -> PA=( curl args for this proxy )
  local t h p u pw s=socks5h n; read -r t h p u pw <<<"$1"; [ "$t" = http ] && s=http; [ "$pw" = - ] && pw=""
  if [ "$t" = xray ]; then   # an Xray outbound: its local test socket (by its line number)
    n=$(grep -nxF -- "$1" "$DIR/proxies" 2>/dev/null | head -1 | cut -d: -f1); PA=(-x "socks5h://127.0.0.1:$((XOUT_TB+${n:-0}))"); return 0; fi
""")

# 4. the router config: Xray lines -> outbound proxyN + test socket
rep("import json, os, re\n", "import json, os, re, base64\n")
rep("""for i,p in enumerate(proxies,1):
    t,h,port,u,pw=(p+['-','-'])[:5]
""", """def xout(b64):   # an Xray line's outbound (bad data -> blackhole: the numbers must not shift)
    try:
        o=json.loads(base64.urlsafe_b64decode(b64+'='*(-len(b64)%4)))
        if not isinstance(o,dict) or not o.get('protocol'): raise ValueError
    except Exception: return {"protocol":"blackhole","settings":{}}
    o={k:v for k,v in o.items() if k not in ('tag','sendThrough','proxySettings')}
    ss=dict(o.get('streamSettings') or {}); so=dict(ss.get('sockopt') or {}); so['mark']=mk; ss['sockopt']=so; o['streamSettings']=ss
    return o
for i,p in enumerate(proxies,1):
    if p[0]=='xray':
        o=xout(p[4] if len(p)>4 else ''); o['tag']=f"proxy{i}"; outs.append(o)
        test_in(f"xtest{i}", int(E['XTB'])+i, f"proxy{i}"); continue
    t,h,port,u,pw=(p+['-','-'])[:5]
""")
rep("""TB=$WARP_TEST_BASE PTB=$V6POOL_TB AP=$API_PORT""", """TB=$WARP_TEST_BASE XTB=$XOUT_TB PTB=$V6POOL_TB AP=$API_PORT""")

# 4b. a user's WebSocket / HTTPUpgrade outbound makes every dialect "deprecated": not a reason to try them all
rep('''    if [ "$v" != "$cached" ] && grep -qi deprecat <<<"$out"; then''',
    '''    if [ "$v" != "$cached" ] && grep -i deprecat <<<"$out" | grep -qviE 'WebSocket|HTTPUpgrade|gRPC'; then''')

# 5. proxy add / addmany
rep("""proxy_cmd(){
  local l t h p u pw tr ms
""", r'''xscrub(){ sed -E 's/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/<id>/g; s/[A-Za-z0-9_+\/=-]{20,}/<…>/g' | cut -c1-160; }
xout_json(){ # xout_json <base64url> -> the outbound with mark (tag x) or rc 1
  python3 -c 'import sys,json,base64
b=sys.argv[1]; o=json.loads(base64.urlsafe_b64decode(b+"="*(-len(b)%4)))
assert isinstance(o,dict) and o.get("protocol")
o={k:v for k,v in o.items() if k not in ("tag","sendThrough","proxySettings")}; o["tag"]="x"
ss=dict(o.get("streamSettings") or {}); so=dict(ss.get("sockopt") or {}); so["mark"]=int(sys.argv[2]); ss["sockopt"]=so; o["streamSettings"]=ss
print(json.dumps(o))' "$1" "$SOMARK" 2>/dev/null; }
proxy_test(){ # proxy_test <line> -> "OK <ip> <loc> <ms>" (rc 0) | "!! <why>" (rc 1). Xray lines in a temporary Xray.
  local t h p u pw tr ms js cfg pid out x="" r=0
  read -r t h p u pw _ <<<"$1"
  if [ "$t" = xray ]; then
    js=$(xout_json "$pw") || { echo "!! not a valid Xray outbound"; return 1; }
    exec 7>"$RUN/warp_try.lock"; flock -w 150 7 || { echo "!! another test is running - try again"; return 1; }
    cfg=$(mktemp --suffix=.json); chmod 600 "$cfg"
    printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":%s,"protocol":"socks","settings":{"udp":false}}],"outbounds":[%s]}\n' "$WARP_TRY_PORT" "$js" > "$cfg"
    if ! out=$("$XRAY" run -test -c "$cfg" 2>&1); then
      rm -f "$cfg"; flock -u 7
      echo "!! this server's Xray ($("$XRAY" version 2>/dev/null | head -1 | awk '{print $2}')) does not take this config: $(grep -iE 'fail|error|unknown|invalid|not ' <<<"$out" | tail -n 1 | sed 's/^.*\] //' | xscrub)"; return 1; fi
    "$XRAY" run -c "$cfg" > "$RUN/xout_try.log" 2>&1 & pid=$!
    sleep 2; x="socks5h://127.0.0.1:$WARP_TRY_PORT"
    if kill -0 $pid 2>/dev/null; then tr=$(cf_trace -x "$x"); ms=$(igping -x "$x"); [ -n "$ms" ] || ms=$(igping -x "$x")
    else tr=""; fi
    kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -f "$cfg"; flock -u 7
  else
    pargs "$1"; tr=$(cf_trace "${PA[@]}"); ms=$(igping "${PA[@]}")
  fi
  [ -n "$tr" ] && [ -n "$ms" ] || { echo "!! $([ "$t" = xray ] && echo "no connection through this config (server down, wrong key / id, or blocked from here)" || echo "proxy does not work") - not added"; return 1; }
  echo "OK $(grep '^ip=' <<<"$tr" | cut -d= -f2) $(grep '^loc=' <<<"$tr" | cut -d= -f2) $ms"; }
proxy_norm(){ # proxy_norm <line> -> the stored line, or rc 1
  local t h p u pw; read -r t h p u pw _ <<<"$1"; t=${t,,}; [ "$t" = socks ] && t=socks5
  case "$t" in http|socks5|xray) ;; *) return 1;; esac
  [ -n "$h" ] && [[ "$p" =~ ^[0-9]+$ ]] || return 1
  [ "$t" = xray ] && { [ -n "$u" ] && [ "$u" != - ] && [ -n "$pw" ] || return 1; }
  echo "$t $h $p ${u:--} ${pw:--}"; }
proxy_cmd(){
  local l t h p u pw tr ms
''')
rep("""    add) shift; if [ $# -eq 0 ] || [ "$1" = - ]; then read -r l; else l="$*"; fi
       read -r t h p u pw <<<"$l"; t=${t,,}; [ "$t" = socks ] && t=socks5
       case "$t" in http|socks5) ;; *) die "usage: proxy add <http|socks5> <host> <port> [user] [pass]";; esac
""", """    add) shift; if [ $# -eq 0 ] || [ "$1" = - ]; then read -r l; else l="$*"; fi
       read -r t h p u pw <<<"$l"; t=${t,,}; [ "$t" = socks ] && t=socks5
       if [ "$t" = xray ]; then
         l=$(proxy_norm "$l") || die "usage: proxy add xray <host> <port> <label> <base64 outbound JSON>"
         grep -qxF "$l" "$DIR/proxies" && { echo "  already in the list"; return; }
         read -r t h p u _ <<<"$l"; echo "  testing $u ($h:$p) ..."
         tr=$(proxy_test "$l") || die "${tr#!! }"
         read -r _ h p ms <<<"$tr"; echo "  OK - exit IP $h ($p)  ${ms}ms"
         echo "$l" >> "$DIR/proxies"; chmod 600 "$DIR/proxies"; apply quiet; echo "  proxy $(nproxies) added"; return; fi
       case "$t" in http|socks5) ;; *) die "usage: proxy add <http|socks5> <host> <port> [user] [pass]";; esac
""")
rep("""    del) [[ "$2" =~ ^[0-9]+$ ]] && [ "$2" -ge 1 ] && [ "$2" -le "$(nproxies)" ] || die "usage: proxy del <number 1-$(nproxies)>"
""", """    addmany) # lines on stdin; each tested; one router reload for all. Out: "  [k] OK - exit IP a (cc)  NNms -> proxy N" | "  [k] !! why"
       local k=0 n0 added=0 r a b c; n0=$(nproxies); touch "$DIR/proxies"
       while IFS= read -r l || [ -n "$l" ]; do
         [ -z "${l// }" ] && continue; k=$((k+1))
         l=$(proxy_norm "$l") || { echo "  [$k] !! not a proxy / outbound line"; continue; }
         grep -qxF "$l" "$DIR/proxies" && { echo "  [$k] already in the list as proxy $(grep -nxF "$l" "$DIR/proxies" | head -1 | cut -d: -f1)"; continue; }
         r=$(proxy_test "$l") || { echo "  [$k] $r"; continue; }
         read -r _ a b c <<<"$r"; echo "$l" >> "$DIR/proxies"; chmod 600 "$DIR/proxies"; added=$((added+1))
         echo "  [$k] OK - exit IP $a ($b)  ${c}ms -> proxy $(nproxies)"
       done
       [ $added -gt 0 ] && { apply quiet; log "proxies: $added added ($(nproxies) now)"; }
       echo "  $added added";;
    del) [[ "$2" =~ ^[0-9]+$ ]] && [ "$2" -ge 1 ] && [ "$2" -le "$(nproxies)" ] || die "usage: proxy del <number 1-$(nproxies)>"
""")
rep("""  proxy [list] | proxy add <http|socks5> <host> <port> [user] [pass] | proxy add -  (same line on stdin) | proxy del <n>
""", """  proxy [list] | proxy add <http|socks5> <host> <port> [user] [pass] | proxy add -  (same line on stdin) | proxy del <n>
  proxy add xray <host> <port> <label> <base64url outbound JSON>   an Xray config (vless / vmess / trojan / ss / hysteria2)
  proxy addmany                        several lines on stdin, each tested, one router reload
""")

open(sys.argv[2], "w", encoding="utf-8", newline="\n").write(src)
print("patched")
