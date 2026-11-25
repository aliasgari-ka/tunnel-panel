#!/usr/bin/env python3
# igproxy agent patch: the user-path check (path_watch) no longer restarts the router for Google alone.
#
# Every user's web traffic (tcp 80/443, REDIRECT to the router) runs through igproxy-xray, so a restart cuts
# all of it at once. path_watch restarted it whenever Google's generate_204 failed twice through the router
# while Google's exit answered on its own - every 10 min, all evening. Seen on خارج اوتباند (GOOGLE=proxy2),
# 2026-11-23: 26 restarts from "user path check failed: Gemini (http 000)", 51 restarts that day; the
# users of the outbound tunnel reported constant disconnects. A restart never repaired Google's exit.
#
# Now: Google failing alone -> repaired as before (another WARP, firewall rebuild), no restart.
# Instagram failing -> restart as before, but outside the users' quiet hours (03-07 Tehran) at most once an
# hour instead of every 10 min.
#
# usage: patch_pathrestart.py <in igproxy.sh> <out>
import sys
src = open(sys.argv[1], encoding='utf-8').read()
n = 0
def sub(old, new, count=1):
    global src, n
    if src.count(old) != count:
        sys.exit(f"anchor found {src.count(old)}x (want {count}): {old[:80]!r}")
    src = src.replace(old, new); n += 1

if 'Google alone fails' in src:
    sys.exit("already patched")
sub('''    elif due restart 600; then log "still broken -> restarting router"; write_conf >/dev/null; reload_xray; sleep 3
    else log "still broken - router was restarted less than 10 min ago, not again"; fi''',
'''    elif [[ "$bad" != *Instagram* ]]; then   # a restart cuts every user's web traffic and never repaired Google's exit
      due pathnorestart 1800 && log "user path:$bad - Google alone fails, its exit answers on its own -> no router restart (it would cut every user)"
    elif { quiet_hours && due restart 600; } || due restart 3600; then log "still broken -> restarting router"; write_conf >/dev/null; reload_xray; sleep 3
    else log "still broken - router was restarted less than $(quiet_hours && echo "10 min" || echo "an hour") ago, not again"; fi''')
open(sys.argv[2], 'w', encoding='utf-8', newline='\n').write(src)
print("patched", n, "places")
