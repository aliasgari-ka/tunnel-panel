#!/usr/bin/env python3
# igproxy agent patch: "All of Google" (set gall on) also covers Google's ad, tag and beacon domains.
#
# On the panel host (2026-11-25) Google stopped placing its IPv4 152.53.86.103 in any country.
# The host keeps gall on so its users' Google leaves from its IPv6 pool, yet in 18 minutes of the
# agent's log its users still reached Google from that IPv4 through domains outside G_GALL:
# pagead2/tpc/ade.googlesyndication.com (28), www.googletagservices.com, beacons(.gcp).gvt2.com.
# They are added. Not added: gvt1.com (Chrome/Play downloads: big files on WARP routes) and
# YouTube (www.youtube.com / ytimg: its video stays on its own route, and the page and the video
# from different IPs break playback).
#
# usage: patch_gall2.py <in igproxy.sh> <out>
import sys
src = open(sys.argv[1], encoding='utf-8').read()
old = "domain:googletagmanager.com domain:recaptcha.net'   # set gall on: ALL Google on Google's WARP (not YouTube video)"
new = "domain:googletagmanager.com domain:recaptcha.net domain:googlesyndication.com domain:googletagservices.com domain:gvt2.com domain:gvt3.com domain:app-measurement.com'   # set gall on: ALL Google on Google's WARP (not YouTube video)"
if 'domain:googlesyndication.com' in src:
    sys.exit("already patched")
if src.count(old) != 1:
    sys.exit(f"anchor found {src.count(old)}x (want 1)")
open(sys.argv[2], 'w', encoding='utf-8', newline='\n').write(src.replace(old, new))
print("patched")
