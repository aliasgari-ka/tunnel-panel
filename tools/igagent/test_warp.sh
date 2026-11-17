#!/bin/bash
# test_warp.sh <igproxy.sh>: the WARP fixes of the agent, each function run against fake state (no network, no root).
A=$1; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
n=$(grep -n '^case "\$c" in help' "$A" | cut -d: -f1); [ -n "$n" ] || { echo "no dispatcher found"; exit 2; }
c0=$(awk -v n="$n" 'NR<n && /^c=/{l=NR} END{print l}' "$A")
head -n $(( ${c0:-n} - 1 )) "$A" > "$T/lib.sh"
mkdir -p "$T/etc" "$T/run" "$T/bin"
# fake system commands (the real ones must not be touched by a test)
cat > "$T/bin/systemctl" <<'X'
#!/bin/bash
case "$*" in *ActiveEnterTimestampMonotonic*) cat "$FAKE/stamp" 2>/dev/null;; *) exit 0;; esac
X
cat > "$T/bin/ss" <<'X'
#!/bin/bash
[ -e "$FAKE/api_up" ] && echo "LISTEN 0 0 127.0.0.1:12398"
exit 0
X
cat > "$T/bin/logger" <<'X'
#!/bin/bash
exit 0
X
chmod +x "$T/bin"/*
export FAKE="$T" PATH="$T/bin:$PATH"
. "$T/lib.sh" >/dev/null 2>&1
DIR="$T/etc"; RUN="$T/run"; CONF="$DIR/config.json"
fail=0; ok(){ echo "  ok   $1"; }; bad(){ echo "  FAIL $1"; fail=1; }
LOG="$T/log"; : > "$LOG"
log(){ echo "$*" >> "$LOG"; }
HOT="$T/hot"; : > "$HOT"
hot_out(){ echo "$1 ${2:-$1}" >> "$HOT"; return 0; }
NOW=0; tehran_now(){ echo "$NOW"; }
at(){ NOW=$(( $1 * 3600 + ${2:-0} * 60 + 86400 * 20000 )); }   # at <Tehran hour> [min]

echo "== quiet hours are Tehran's 03-07"
for h in 0 2; do at $h 59; quiet_hours && bad "0$h:59 counted as quiet"; done
at 3 0; quiet_hours && ok "03:00 quiet" || bad "03:00 not quiet"
at 6 59; quiet_hours && ok "06:59 quiet" || bad "06:59 not quiet"
at 7 0; quiet_hours && bad "07:00 counted as quiet" || ok "07:00 not quiet"
at 15 30; quiet_hours && bad "15:30 counted as quiet" || ok "15:30 not quiet"
unset -f tehran_now; . <(grep '^tehran_now(){' "$T/lib.sh")
d=$(( $(date -u +%s) + 12600 )); [ "$(tehran_now)" -ge "$d" ] && [ "$(tehran_now)" -le $((d + 2)) ] && ok "tehran_now = UTC+3:30" || bad "tehran_now"
[[ "$(tehran_day)" =~ ^20[0-9]{2}-[0-9]{2}-[0-9]{2}$ ]] && ok "tehran_day $(tehran_day)" || bad "tehran_day: $(tehran_day)"
tehran_now(){ echo "$NOW"; }

echo "== geosite: loaded only in the quiet hours, once a night"
R=0; apply_reload(){ R=$((R+1)); }; geo_update(){ :; }; has(){ [ -e "$DIR/$1" ]; }
date +%s > "$DIR/geo_checked"
echo new > "$DIR/geosite.dat.next"; echo old > "$DIR/geosite.dat"
at 9 0; geo_maint; [ $R = 0 ] && [ -s "$DIR/geosite.dat.next" ] && ok "09:00 Tehran: not loaded" || bad "loaded by day"
at 4 0; geo_maint; [ $R = 1 ] && [ "$(cat "$DIR/geosite.dat")" = new ] && ok "04:00 Tehran: loaded, one restart" || bad "not loaded at night (R=$R)"
echo newer > "$DIR/geosite.dat.next"; at 5 0; geo_maint; [ $R = 1 ] && ok "05:00 same night: a second file waits" || bad "second restart the same night"
NOW=$((NOW + 86400)); geo_maint; [ $R = 2 ] && ok "next night: loaded" || bad "next night not loaded (R=$R)"

echo "== repair backoff"
rm -f "$RUN"/wrep*
rep_may 1 && rep_may 1 && ok "first two repairs allowed" || bad "first repairs refused"
rep_may 1 && bad "third repair in an hour allowed" || ok "third repair in an hour refused"
grep -q "WARP 1 keeps failing.*1 h" "$LOG" && ok "logged, 1 h" || bad "no log line: $(tail -n 1 "$LOG")"
rep_may 1 && bad "repair allowed during the pause" || ok "paused"
rep_may 2 && ok "another WARP is not paused" || bad "WARP 2 paused too"
echo $(( $(date +%s) - 10 )) > "$RUN/wrep_wait_1"      # the pause just ended
rep_may 1; rep_may 1; rep_may 1; grep -q "WARP 1 keeps failing.*6 h" "$LOG" && ok "goes on: 6 h" || bad "no 6 h step: $(tail -n 1 "$LOG")"

echo "== speed rule"
rm -f "$DIR/slow_new" "$DIR/warp_via"
slow_may && slow_may && ok "two a day" || bad "refused early"
slow_may && bad "third new account for speed in a day" || ok "third refused"
rm -f "$DIR/slow_new"; echo "1.2.3.4:24080" > "$DIR/warp_via"
slow_may && bad "a forwarded WARP replaced for its speed" || ok "never through a forward"
rm -f "$DIR/warp_via"

echo "== a router restart from outside: out-of-pool WARPs are put out again"
: > "$HOT"; : > "$LOG"; rm -f "$RUN"/wout_* "$RUN/xray_seen" "$T/api_up"
echo 111 > "$T/stamp"; touch "$T/api_up"; echo ip > "$RUN/wout_2"
pool_reout; [ ! -s "$HOT" ] && [ "$(cat "$RUN/xray_seen")" = 111 ] && ok "first look only remembers the router" || bad "acted on the first look"
pool_reout; [ ! -s "$HOT" ] && ok "same router: nothing" || bad "acted without a restart"
echo 222 > "$T/stamp"; rm -f "$T/api_up"
pool_reout; [ ! -s "$HOT" ] && [ "$(cat "$RUN/xray_seen")" = 111 ] && ok "router not listening yet: waits" || bad "did not wait for the router"
touch "$T/api_up"; pool_reout
grep -qx "warp2 bad-warp2" "$HOT" && [ "$(cat "$RUN/xray_seen")" = 222 ] && grep -q "1 WARP(s) outside the pool put out again" "$LOG" && ok "WARP 2 out again after the restart" || bad "not re-outed: $(cat "$HOT") / $(cat "$LOG")"

echo "== the last pool member dies: the spare outside takes over"
: > "$HOT"; : > "$LOG"; rm -f "$RUN"/wout_* "$RUN"/wsel_* "$RUN/pool_ip"
printf 'k1 172.16.0.2/32 e:1 id1\nk2 172.16.0.2/32 e:1 id2\n' > "$DIR/warps"; echo "IG=warp6" > "$DIR/routes"; touch "$DIR/warp_spread"
echo ip > "$RUN/wout_2"
cf_trace(){ :; }                       # WARP 1 answers nothing
warp_really_down(){ return 0; }; warp_try(){ echo "warp=on ip=9.9.9.9 "; }; gpin(){ return 1; }
declare -A PF=([1]=1)
pool_tick
[ ! -e "$RUN/wout_2" ] && grep -qx "warp2 warp2" "$HOT" && ok "spare WARP 2 taken into the pool" || bad "spare not promoted: $(cat "$HOT")"
[ "$(cat "$RUN/wout_1" 2>/dev/null)" = down ] && grep -qx "warp1 bad-warp1" "$HOT" && ok "dead WARP 1 out as down" || bad "dead one not out: $(cat "$RUN/wout_1" 2>/dev/null)"
# it works again on warp6: stays outside as the spare
: > "$HOT"; pool_retry
[ "$(cat "$RUN/wout_1")" = ip ] && [ ! -s "$HOT" ] && ok "repaired WARP 1 waits outside as the spare (warp6)" || bad "came back into a warp6 pool: $(cat "$RUN/wout_1") $(cat "$HOT")"
# no spare outside: the last one is kept
: > "$HOT"; : > "$LOG"; rm -f "$RUN"/wout_*; printf 'k1 172.16.0.2/32 e:1 id1\n' > "$DIR/warps"; PF=([1]=1)
pool_tick; [ ! -e "$RUN/wout_1" ] && grep -q "last WARP in the pool - kept" "$LOG" && ok "no spare: the last one stays" || bad "last member thrown out"

echo "== a tie keeps the pool's exit"
printf 'k1 a e:1 id1\nk2 a e:1 id2\n' > "$DIR/warps"; rm -f "$RUN"/wout_*; : > "$HOT"; : > "$LOG"; PF=()
echo "2a09:bac5::1" > "$RUN/pool_ip"                       # the carrier's exit (sorts AFTER the newcomer's)
cf_trace(){ case "$*" in *12351*) printf 'warp=on\nip=2a09:bac5::1\n';; *) printf 'warp=on\nip=2a09:bac1::9\n';; esac; }
pool_tick
[ "$(cat "$RUN/wout_2" 2>/dev/null)" = ip ] && [ ! -e "$RUN/wout_1" ] && ok "the newcomer goes out, the carrier stays" || bad "the carrier lost the tie: wout_1=$(cat "$RUN/wout_1" 2>/dev/null) wout_2=$(cat "$RUN/wout_2" 2>/dev/null)"

echo "== a missing account waits for the quiet hours while a WARP carries the users"
: > "$LOG"; rm -f "$RUN"/wout_* "$RUN"/last_* "$RUN/fill_next" "$RUN/igcc_stop"; echo 3 > "$DIR/min_warps"
REG=0; warp_new_good(){ REG=$((REG+1)); return 1; }; warp_load_peak(){ echo 0; }; warp_test(){ echo "warp=on"; }; apply(){ :; }
at 15 0; warp_fill; [ $REG = 0 ] && grep -q "made in the quiet hours" "$LOG" && ok "15:00 Tehran: waits" || bad "signed up by day (REG=$REG) $(cat "$LOG")"
warp_test(){ :; }; warp_fill; [ $REG -gt 0 ] && ok "no WARP carries the users: made at once" || bad "did not fill with no carrier"
REG=0; warp_test(){ echo "warp=on"; }; rm -f "$RUN/fill_next"; at 4 0; warp_fill; [ $REG -gt 0 ] && ok "04:00 Tehran: made" || bad "did not fill at night"
echo; [ $fail = 0 ] && echo "ALL OK" || echo "SOME FAILED"; exit $fail
