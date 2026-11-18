#!/usr/bin/env python3
# igproxy agent patch: Shazam as its own service (route SHAZAM, direct by default).
#
# Shazam's own API (amp / beacon / config / cdn.shazam.com) sits behind Google's front end, which
# answers 403 to a server IP it places in Iran, so the app does not open through such a server.
# The Apple hosts the app also uses (amp-api.shazam.apple.com, shazam-events.cdn-apple.com,
# *.itunes.apple.com) answer from every server and stay where they are. With a route of its own
# the panel's Auto (igsvc.go) moves only shazam.com to WARP / a proxy on the servers Google refuses.
#
# usage: patch_shazam.py <in igproxy.sh> <out>
import sys
src = open(sys.argv[1], encoding='utf-8').read()
n = 0
def sub(old, new, count=1):
    global src, n
    if src.count(old) != count:
        sys.exit(f"anchor found {src.count(old)}x (want {count}): {old[:80]!r}")
    src = src.replace(old, new); n += 1

if 'G_SHAZAM=' in src:
    sys.exit("already patched")
sub(' PRIME TWITCH APPLE GAMES DEV"', ' PRIME TWITCH APPLE SHAZAM GAMES DEV"')
sub("\nG_GAMES='", "\nG_SHAZAM='domain:shazam.com'   # its API is behind Google's front end (403 by the IP's country); the Apple hosts of the app are not here\nG_GAMES='")
sub('APPLE) echo "Apple Music/iCloud";;', 'APPLE) echo "Apple Music/iCloud";; SHAZAM) echo Shazam;;')
open(sys.argv[2], 'w', encoding='utf-8', newline='\n').write(src)
print("patched", n, "places")
