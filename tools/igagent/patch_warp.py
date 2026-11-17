#!/usr/bin/python3 -I
"""patch_warp.py <igproxy.sh in> <out>: the WARP fixes of 2026-11-17 on agent b5795541.
Every replacement must match exactly once, or nothing is written."""
import io, sys

src, dst = sys.argv[1], sys.argv[2]
s = io.open(src, encoding='utf-8', newline='').read()
assert '\r' not in s
P = []

# ---- 1. the users' quiet hours (Tehran), not the server's clock
P.append((r'''  [ $((now - $(cat "$f" 2>/dev/null || echo 0))) -ge "$2" ] || return 1; echo "$now" > "$f"; }
''', r'''  [ $((now - $(cat "$f" 2>/dev/null || echo 0))) -ge "$2" ] || return 1; echo "$now" > "$f"; }
# The users are in Iran: what cuts them (a router restart) is kept for THEIR quiet hours, 03-07 Tehran time
# (UTC+3:30, no summer time) - whatever this server's own clock says. "04-06 on the server" was 07:30-09:30 in
# Tehran on a UTC server: 10 of 15 servers restarted after their users woke up (2026-11-17).
tehran_now(){ echo $(( $(date -u +%s) + 12600 )); }
quiet_hours(){ local h; h=$(( $(tehran_now) % 86400 / 3600 )); [ "$h" -ge 3 ] && [ "$h" -lt 7 ]; }
tehran_day(){ date -u -d "@$(tehran_now)" +%F; }
xray_stamp(){ systemctl show -p ActiveEnterTimestampMonotonic --value igproxy-xray 2>/dev/null; }   # changes with every (re)start of the router
'''))

# ---- 2. geosite: loaded in the quiet hours, once a night
P.append((r'''  if [ -s "$DIR/geosite.dat.next" ] && [ "$(date +%-H)" -ge 4 ] && [ "$(date +%-H)" -lt 6 ]; then
    mv "$DIR/geosite.dat.next" "$DIR/geosite.dat"; apply_reload; log "geosite: new domain lists loaded (night reload)"
  fi''', r'''  # loading them restarts the router = every user of this server is cut for a few seconds: only in the users'
  # quiet hours, and once a night (the 20-hourly check landed inside the window and loaded a second file an hour
  # after the first: xe107, 2026-11-17)
  if [ -s "$DIR/geosite.dat.next" ] && quiet_hours && [ "$(cat "$DIR/geo_night" 2>/dev/null)" != "$(tehran_day)" ]; then
    tehran_day > "$DIR/geo_night"
    mv "$DIR/geosite.dat.next" "$DIR/geosite.dat"; apply_reload; log "geosite: new domain lists loaded (night reload)"
  fi'''))
P.append((r'''log "geosite: new domain lists downloaded - loaded tonight (04:00-06:00)"''',
          r'''log "geosite: new domain lists downloaded - loaded in the users' quiet hours (03-07 Tehran time)"'''))

# ---- 3. a router restart must not put the WARPs that are out of the pool back among the users
P.append((r'''    [ -e "$f" ] || continue; has warp_spread && grep -qsE 'music|ipnew' "$f" && hot_out "warp${f##*_}" "bad-warp${f##*_}" || rm -f "$f"; done
  return 0; }''', r'''    [ -e "$f" ] || continue; has warp_spread && grep -qsE 'music|ipnew' "$f" && hot_out "warp${f##*_}" "bad-warp${f##*_}" || { rm -f "$f"; hot_out "warp${f##*_}"; }; done   # (in again for sure: the guard may have put it out a moment ago, pool_reout)
  xray_stamp > "$RUN/xray_seen"
  return 0; }'''))
P.append((r'''pool_in(){ hot_out "warp$1" && rm -f "$RUN/wout_$1" && log "guard: WARP $1 works again -> back in the pool ($(pool_size) WARPs)"; }
''', r'''pool_in(){ hot_out "warp$1" && rm -f "$RUN/wout_$1" && log "guard: WARP $1 works again -> back in the pool ($(pool_size) WARPs)"; }
pool_reout(){ # (guard) the router was (re)started by something else than reload_xray - systemctl, a crash, an install: it
  # loads every WARP as "warpN" again, also the ones kept out of the pool, and nothing put them out again: Instagram
  # left through two exit IPs at once for 3 h 47 min (xe108, 2026-11-17). Out again, as soon as the router answers.
  local s f n k=0; s=$(xray_stamp); [ -n "$s" ] || return 0
  [ "$s" = "$(cat "$RUN/xray_seen" 2>/dev/null)" ] && return 0
  ss -Htln "( sport = :$API_PORT )" 2>/dev/null | grep -q . || return 0          # not up yet: the next tick
  if [ -s "$RUN/xray_seen" ]; then
    for f in "$RUN"/wout_*; do [ -e "$f" ] || continue; n=${f##*_}; hot_out "warp$n" "bad-warp$n" && k=$((k+1)); done
    [ $k -gt 0 ] && log "guard: the router was restarted -> $k WARP(s) outside the pool put out again"
  fi
  echo "$s" > "$RUN/xray_seen"; }
slow_may(){ # may a pool member get a new account for its speed? Not a WARP that enters through a forward (warp-via):
  # its ceiling is the forward's, no new account can pass - NL replaced its Instagram carrier every 32 minutes all
  # day, a Cloudflare sign-up and a new exit IP for the users each time. Elsewhere at most 2 a day.
  [ -s "$DIR/warp_via" ] && return 1
  local now; now=$(date +%s)
  [ "$(awk -v c=$((now - 86400)) '$1>=c' "$DIR/slow_new" 2>/dev/null | wc -l)" -lt 2 ] || return 1
  { awk -v c=$((now - 86400)) '$1>=c' "$DIR/slow_new" 2>/dev/null; echo "$now"; } > "$DIR/slow_new.tmp" && mv "$DIR/slow_new.tmp" "$DIR/slow_new"; }
'''))
P.append((r'''      [ $((now - ${last_p:-0})) -ge $POOL_TICK_SEC ] && { last_p=$now; pool_tick; }''',
          r'''      [ $((now - ${last_p:-0})) -ge $POOL_TICK_SEC ] && { last_p=$now; pool_reout; pool_tick; }'''))

# ---- 4. the last pool member is down: a healthy WARP outside the pool takes over now
P.append((r'''      if warp_really_down "$i"; then echo "down 0" > "$RUN/wsel_$i"; log "guard: WARP $i down -> the router skips it, the slow checks repair it"
      else PF[$i]=0; fi''', r'''      if warp_really_down "$i"; then echo "down 0" > "$RUN/wsel_$i"; log "guard: WARP $i down -> the router skips it, the slow checks repair it"
        # the last one carrying the users (on warp6 the pool is always one): a healthy WARP waiting outside takes over
        # now (pool_out's rescue) - before, the users fell to the proxy / the server's own IP until the repair
        [ "$(pool_size)" -le 1 ] && pool_out "$i" down "is down"
      else PF[$i]=0; fi'''))
# on a tie the pool keeps the exit it has (a brand-new account won over the carrier: the users' Instagram IP changed for nothing)
P.append((r'''    maj=$(cat "$d"/* | sort | uniq -c | sort -k1,1nr -k2 | awk 'NR==1{print $2}'); echo "$maj" > "$RUN/pool_ip"''',
          r'''    maj=$(cat "$d"/* | sort | uniq -c | sort -k1,1nr -k2 | awk -v p="$(cat "$RUN/pool_ip" 2>/dev/null)" 'NR==1{c=$1; m=$2} $1==c && $2==p{m=p} END{print m}'); echo "$maj" > "$RUN/pool_ip"'''))
P.append((r'''      [ -e "$d/$i" ] && [ "$(cat "$d/$i")" != "$maj" ] && pool_out $i ip "exit IP $(cat "$d/$i") differs from the pool's $maj (Instagram needs one IP)"
    done
  fi''', r'''      [ -e "$d/$i" ] && [ "$(cat "$d/$i")" != "$maj" ] && pool_out $i ip "exit IP $(cat "$d/$i") differs from the pool's $maj (Instagram needs one IP)"
    done
  elif ig_on_warp && [ "$(ls "$d" | wc -l)" = 1 ]; then cat "$d"/* > "$RUN/pool_ip"     # one member: its exit is the pool's (the tie rule above needs it)
  fi'''))
# warp6: a WARP that was out for "down" and works again stays outside as the spare (its own IPv6 is never the pool's)
P.append((r'''    if [ "$why" = ip ]; then          # IPv4 route: the test Xray shows the real exit IP -> back only with the pool's IP
      [ "${t##*ip=}" = "$(cat "$RUN/pool_ip" 2>/dev/null) " ] || { touch "$f"; continue; }
    fi''', r'''    if [ "$why" = ip ]; then          # IPv4 route: the test Xray shows the real exit IP -> back only with the pool's IP
      [ "${t##*ip=}" = "$(cat "$RUN/pool_ip" 2>/dev/null) " ] || { touch "$f"; continue; }
    elif [ "$(route_of IG)" = warp6 ] && [ "$(pool_size)" -ge 1 ]; then echo ip > "$f"; continue     # works again: the spare outside the pool
    fi'''))

# ---- 5. the speed rule
P.append((r'''    elif [ "$sp" -lt $((min / 2)) ] && [ -z "$slow" ]; then slow=$i; echo "only ${sp} Mbps" > "$RUN/wnew_$i"; fi   # members carry users: half the minimum''',
          r'''    elif [ "$sp" -lt $((min / 2)) ] && [ -z "$slow" ] && slow_may; then slow=$i; echo "only ${sp} Mbps" > "$RUN/wnew_$i"; fi   # members carry users: half the minimum'''))

# ---- 6. repair backoff
P.append((r'''    [ $f -lt $WARP_FAIL_LIMIT ] && continue
    rm -f "$RUN/wfail_$n"
    if warp_repair $n; then warp_live $n || restart=1; fi''', r'''    [ $f -lt $WARP_FAIL_LIMIT ] && continue
    rm -f "$RUN/wfail_$n"
    rep_may $n || continue
    if warp_repair $n; then warp_live $n || restart=1; fi'''))
P.append((r'''warp_maint(){ # test every WARP; repair after WARP_FAIL_LIMIT failed checks; swap live
''', r'''rep_may(){ # rep_may <n> : may WARP n be repaired now? 3 repairs within an hour = the repair does not help (one server
  # "fixed" the same WARP on the same endpoint every 8 minutes for days: 73 repairs in 48 h) -> the next one after
  # 1 h, and after 6 h while it goes on
  local f="$RUN/wrep_$1" now u="" w; now=$(date +%s); [ -s "$RUN/wrep_wait_$1" ] && read -r u < "$RUN/wrep_wait_$1"
  [ "$now" -lt "${u:-0}" ] && return 1
  { awk -v c=$((now - 3600)) '$1>=c' "$f" 2>/dev/null; echo "$now"; } > "$f.tmp" && mv "$f.tmp" "$f"
  [ "$(wc -l < "$f")" -ge 3 ] || return 0
  if [ -n "$u" ] && [ $((now - u)) -lt 43200 ]; then w=21600; else w=3600; fi
  echo $((now + w)) > "$RUN/wrep_wait_$1"; : > "$f"
  log "WARP $1 keeps failing right after its repair (3 in an hour) -> its next repair in $((w / 3600)) h"; return 1; }
fill_can_wait(){ # does a WARP of the pool still carry the users?
  local i; for i in $(non_gw); do [ -f "$RUN/wout_$i" ] && continue; [ -n "$(warp_test $i)" ] && return 0; done; return 1; }
warp_maint(){ # test every WARP; repair after WARP_FAIL_LIMIT failed checks; swap live
'''))

# ---- 7. a missing account is made in the quiet hours while a WARP still carries the users
P.append((r'''  [ "$(date +%s)" -lt "$(cat "$RUN/igcc_stop" 2>/dev/null || echo 0)" ] && return 0
  log "only $have of $want WARPs on this server -> adding $((want-have))"''', r'''  [ "$(date +%s)" -lt "$(cat "$RUN/igcc_stop" 2>/dev/null || echo 0)" ] && return 0
  # adding an account restarts the router (every user of this server is cut for a few seconds): while a WARP still
  # carries them, the missing one is made in the users' quiet hours
  if ! quiet_hours && fill_can_wait; then
    due fillwait 21600 && log "only $have of $want WARPs - a WARP still carries the users: the missing one is made in the quiet hours (03-07 Tehran time)"
    return 0; fi
  log "only $have of $want WARPs on this server -> adding $((want-have))"'''))

for a, b in P:
    n = s.count(a)
    if n != 1:
        sys.exit('NOT APPLIED (%d matches): %s' % (n, a[:90]))
    s = s.replace(a, b)
io.open(dst, 'w', encoding='utf-8', newline='').write(s)
print('patched: %d changes' % len(P))
