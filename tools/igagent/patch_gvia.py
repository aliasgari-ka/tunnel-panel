#!/usr/bin/env python3
# igproxy agent patch: on a server with warp-via, Google's own WARPs enter Cloudflare through the
# forwards too.
#
# Cloudflare exits a WARP in the datacenter it enters. warp-via (NL: UDP forwards on two German
# servers) was applied only to the WARPs that are not Google's own, because it was made for
# Instagram. Google's own WARPs kept entering in Amsterdam, and Google places most Amsterdam WARP
# IPv6 addresses badly: the signed-out Gemini app names no place there (signed-in Gemini refused),
# the keyless page reads US or .ru. A Google WARP whose stored endpoint happened to be a forward
# read "Nuremberg, Germany". So Gemini on هلند1 broke whenever Google's WARP changed to a repaired or
# new account (2026-11-19 03:18, 2026-11-21 03:31 and 05:52 Tehran time): those are scanned on
# Cloudflare's own endpoints only and come back entering in Amsterdam.
#
# Now: with warp-via set every WARP of the server (kernel WARPs aside) is built on a forward, and
# the endpoint scan of a Google WARP tries the forwards first, as Instagram's already did.
# A server without warp-via is not changed at all.
#
# usage: patch_gvia.py <in igproxy.sh> <out>
import sys
src = open(sys.argv[1], encoding='utf-8').read()
n = 0
def sub(old, new, count=1):
    global src, n
    if src.count(old) != count:
        sys.exit(f"anchor found {src.count(old)}x (want {count}): {old[:80]!r}")
    src = src.replace(old, new); n += 1

if 'if via and i not in kw: ep=' in src:
    sys.exit("already patched")
sub("# warp-via: the WARPs that are not Google's own reach Cloudflare through a UDP forward on another server (ip:port ->",
    "# warp-via: the WARPs (Google's own too) reach Cloudflare through a UDP forward on another server (ip:port ->")
sub("    if via and i not in gset and i not in kw: ep=via[(i-1)%len(via)]",
    "    # Google's own WARPs too: entering in Amsterdam, Google names no place for most of them (Gemini refused)\n"
    "    if via and i not in kw: ep=via[(i-1)%len(via)]")
sub('''  [[ "$3" == *ig* ]] && [ -s "$DIR/warp_via" ] && eps=''',
    '''  [[ "$3" == *ig* || "$3" == *gem* ]] && [ -s "$DIR/warp_via" ] && eps=''')
sub("(WARPs that are not Google's own connect through these)", "(the WARPs connect through these)")
open(sys.argv[2], 'w', encoding='utf-8', newline='\n').write(src)
print("patched", n, "places")
