#!/bin/bash
# test_pathrestart.sh <igproxy.sh>: path_watch with fakes - Google failing alone never restarts the router,
# Instagram failing still does (no network, no root).
A=$1; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
n=$(grep -n '^path_watch()' "$A" | cut -d: -f1); [ -n "$n" ] || { echo "no path_watch"; exit 2; }
awk -v n="$n" 'NR>=n{print} NR>n && /^}/{exit}' "$A" > "$T/pw.sh"
n=$(grep -n '^due()' "$A" | cut -d: -f1); sed -n "${n},$((n+2))p" "$A" > "$T/due.sh"
fail=0
run(){ # run <name> <google route> <ig route> <google ok 0|1> <ig ok 0|1> <quiet 0|1> <want restart 0|1>
  rm -rf "$T/run"; mkdir -p "$T/run"
  ( RUN="$T/run"; PATH_SEC=0; GR=$2; IR=$3; GOK=$4; IOK=$5; Q=$6
    . "$T/due.sh"; . "$T/pw.sh"
    route_of(){ case "$1" in GOOGLE) echo "$GR";; IG) echo "$IR";; esac; }
    via_router(){ if [ "$GOK" = 1 ]; then VR_CODE=204; VR_EXIT=proxy2; else VR_CODE=000; VR_EXIT=""; fi; }
    ig_up(){ [ "$IOK" = 1 ]; }; ig_on_warp(){ return 1; }; warp_gem_switch(){ :; }
    path_ok(){ { [ "$1" = 0 ] || [ "$GOK" = 1 ]; } && { [ "$2" = 0 ] || [ "$IOK" = 1 ]; }; }
    fw_ok(){ return 0; }; refresh(){ :; }; sleep(){ :; }; exits_ok(){ return 0; }; write_conf(){ :; }
    quiet_hours(){ [ "$Q" = 1 ]; }; reload_xray(){ echo RESTART >> "$RUN/restarts"; }; log(){ echo "    log: $*" >> "$RUN/log"; }
    for i in 1 2 3; do path_watch; done )
  got=0; [ -s "$T/run/restarts" ] && got=1
  if [ $got = "$7" ]; then echo "ok   $1"; else echo "FAIL $1 (restart=$got, want $7)"; cat "$T/run/log"; fail=1; fi
}
run "Google alone fails -> no restart"            proxy2 proxy2 0 1 0 0
run "Google alone fails, quiet hours -> none"     warp   direct 0 1 1 0
run "Instagram fails -> restart"                  proxy2 proxy2 1 0 0 1
run "both fail -> restart"                        proxy2 proxy2 0 0 0 1
run "all fine -> no restart"                      proxy2 proxy2 1 1 0 0
# once an hour outside the quiet hours: a second failing run 10 min later does not restart again
rm -rf "$T/run2"; mkdir -p "$T/run2"
( RUN="$T/run2"; . "$T/due.sh"; due restart 3600 >/dev/null; echo $(( $(date +%s) - 700 )) > "$RUN/last_restart"
  quiet_hours(){ return 1; }; if { quiet_hours && due restart 600; } || due restart 3600; then echo again; fi ) > "$T/r2"
[ -s "$T/r2" ] && { echo "FAIL restarted again 12 min later outside the quiet hours"; fail=1; } || echo "ok   no second restart within the hour"
exit $fail
