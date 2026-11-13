#!/usr/bin/env python3
# igproxy agent patch: many more services (AI, social, messaging, video, developer) + live
# routing swap (xray api adrules) instead of a router restart when only the rules changed.
# usage: patch_svc.py <in igproxy.sh> <out>
import sys, re
src = open(sys.argv[1], encoding='utf-8').read()
n = 0
def sub(old, new, count=1):
    global src, n
    if src.count(old) != count:
        sys.exit(f"anchor found {src.count(old)}x (want {count}): {old[:80]!r}")
    src = src.replace(old, new); n += 1

NEW = "OPENAI CLAUDE COPILOT PERPLEX GROK AICODE X TIKTOK REDDIT LINKEDIN PINTEREST TELEGRAM WHATSAPP DISCORD NETFLIX DISNEY PRIME TWITCH APPLE GAMES DEV"

sub('SVCS="IG GOOGLE YTM ADULT SPOTIFY SCLOUD SNAP CUSTOM"\nWIDE_SVCS="ADULT SPOTIFY SCLOUD SNAP CUSTOM"',
    f'SVX="{NEW}"   # the newer services (domain-only, like Spotify)\n'
    'SVCS="IG GOOGLE YTM ADULT SPOTIFY SCLOUD SNAP $SVX CUSTOM"\nWIDE_SVCS="ADULT SPOTIFY SCLOUD SNAP $SVX CUSTOM"')

LISTS = r'''
# the newer services: Xray domain lists (hosts + CDNs; no Google domain here: Google always wins first)
G_OPENAI='domain:openai.com domain:chatgpt.com domain:oaistatic.com domain:oaiusercontent.com domain:sora.com domain:chat.com domain:openai.org domain:openaiapi-site.azureedge.net'
G_CLAUDE='domain:claude.ai domain:claude.com domain:anthropic.com domain:claudeusercontent.com domain:clau.de'
G_COPILOT='domain:copilot.microsoft.com domain:copilot.com domain:copilot.cloud.microsoft domain:bing.com domain:bingapis.com domain:bing.net'
G_PERPLEX='domain:perplexity.ai domain:pplx.ai domain:perplexity.com'
G_GROK='domain:grok.com domain:x.ai'
G_AICODE='domain:cursor.com domain:cursor.sh domain:cursorapi.com domain:codeium.com domain:windsurf.com domain:githubcopilot.com domain:huggingface.co domain:hf.co domain:mistral.ai domain:poe.com domain:character.ai domain:midjourney.com domain:elevenlabs.io domain:suno.com domain:runwayml.com domain:replit.com domain:v0.dev domain:lovable.dev domain:bolt.new domain:deepseek.com domain:openrouter.ai'
G_X='domain:x.com domain:twitter.com domain:twimg.com domain:t.co domain:pscp.tv domain:periscope.tv domain:twitter.co'
G_TIKTOK='domain:tiktok.com domain:tiktokv.com domain:tiktokv.us domain:tiktokv.eu domain:tiktokcdn.com domain:tiktokcdn-us.com domain:tiktokcdn-eu.com domain:byteoversea.com domain:ibytedtos.com domain:ibyteimg.com domain:muscdn.com domain:musical.ly domain:tik-tokapi.com domain:ttwstatic.com domain:bytefcdn-oversea.com domain:ttlivecdn.com domain:tiktokw.us domain:tiktokw.eu'
G_REDDIT='domain:reddit.com domain:redd.it domain:redditmedia.com domain:redditstatic.com domain:reddituploads.com domain:redditspace.com'
G_LINKEDIN='domain:linkedin.com domain:licdn.com domain:lnkd.in'
G_PINTEREST='domain:pinterest.com domain:pinimg.com domain:pin.it domain:pinterest.de domain:pinterest.co.uk domain:pinterest.fr'
G_TELEGRAM='domain:telegram.org domain:t.me domain:telegram.me domain:telegra.ph domain:telesco.pe domain:tdesktop.com domain:cdn-telegram.org domain:telegram-cdn.org domain:graph.org'
IP_TELEGRAM='91.105.192.0/23 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22 91.108.16.0/22 91.108.20.0/22 91.108.56.0/22 95.161.64.0/20 149.154.160.0/20 185.76.151.0/24 2001:67c:4e8::/48 2001:b28:f23c::/47 2001:b28:f23f::/48 2a0a:f280::/32'   # the apps (no domain name): caught on 80/443 by wide catch
G_WHATSAPP='domain:whatsapp.com domain:whatsapp.net domain:wa.me domain:whatsapp.biz domain:whatsapp.tv'
G_DISCORD='domain:discord.com domain:discord.gg domain:discordapp.com domain:discordapp.net domain:discord.media domain:discordcdn.com domain:discord.dev domain:dis.gd domain:discordstatus.com'
G_NETFLIX='domain:netflix.com domain:netflix.net domain:nflxext.com domain:nflximg.com domain:nflximg.net domain:nflxso.net domain:nflxvideo.net domain:fast.com'
G_DISNEY='domain:disneyplus.com domain:disney-plus.net domain:dssott.com domain:bamgrid.com domain:disneystreaming.com domain:disney.io domain:dssedge.com'
G_PRIME='domain:primevideo.com domain:amazonvideo.com domain:aiv-cdn.net domain:aiv-delivery.net domain:pv-cdn.net full:atv-ps.amazon.com full:atv-ps-eu.amazon.com full:atv-ps-fe.amazon.com full:atv-ext.amazon.com full:atv-ext-eu.amazon.com full:atv-ext-fe.amazon.com'
G_TWITCH='domain:twitch.tv domain:ttvnw.net domain:jtvnw.net domain:twitchcdn.net domain:twitchsvc.net domain:twitch.a2z.com domain:ext-twitch.tv'
G_APPLE='full:music.apple.com full:tv.apple.com domain:itunes.apple.com domain:music.apple.com full:amp-api.music.apple.com full:amp-api-edge.music.apple.com domain:mzstatic.com domain:icloud.com domain:icloud-content.com domain:apple-cloudkit.com'
G_GAMES='domain:steampowered.com domain:steamcommunity.com domain:steamstatic.com domain:steamcontent.com domain:steamserver.net domain:steam-chat.com domain:steamgames.com domain:valvesoftware.com domain:epicgames.com domain:epicgames.dev domain:unrealengine.com domain:riotgames.com domain:ea.com domain:playstation.com domain:playstation.net domain:xboxlive.com domain:battle.net domain:blizzard.com'
G_DEV='domain:github.com domain:githubusercontent.com domain:githubassets.com domain:github.io domain:ghcr.io domain:githubapp.com domain:docker.com domain:docker.io domain:npmjs.com domain:npmjs.org domain:yarnpkg.com domain:pypi.org domain:pythonhosted.org domain:crates.io domain:rust-lang.org domain:gitlab.com domain:nodejs.org domain:anaconda.com domain:anaconda.org domain:gradle.org domain:maven.org domain:jetbrains.com domain:hashicorp.com domain:quay.io domain:k8s.io domain:terraform.io'
# geosite categories that add to them (only those this geosite.dat/Xray accepts are used: geo_ok)
GEO_SVX="OPENAI:geosite:openai CLAUDE:geosite:anthropic PERPLEX:geosite:perplexity X:geosite:twitter TIKTOK:geosite:tiktok REDDIT:geosite:reddit LINKEDIN:geosite:linkedin PINTEREST:geosite:pinterest TELEGRAM:geosite:telegram WHATSAPP:geosite:whatsapp DISCORD:geosite:discord NETFLIX:geosite:netflix DISNEY:geosite:disney PRIME:geosite:primevideo TWITCH:geosite:twitch GAMES:geosite:steam DEV:geosite:github DEV:geosite:docker"
'''
sub('GEO_ALL="$GEO_IG $GEO_GOOGLE $GEO_ADULT $GEO_SPOTIFY $GEO_SCLOUD"',
    LISTS.strip('\n') + '\nGEO_ALL="$GEO_IG $GEO_GOOGLE $GEO_ADULT $GEO_SPOTIFY $GEO_SCLOUD $(for x in $GEO_SVX; do printf "%s " "${x#*:}"; done)"')

sub('SNAP) echo Snapchat;; CUSTOM)',
    'SNAP) echo Snapchat;; OPENAI) echo ChatGPT;; CLAUDE) echo Claude;; COPILOT) echo "Copilot/Bing";; PERPLEX) echo Perplexity;; GROK) echo Grok;;\n'
    '  AICODE) echo "AI tools (Cursor...)";; X) echo "X/Twitter";; TIKTOK) echo TikTok;; REDDIT) echo Reddit;; LINKEDIN) echo LinkedIn;; PINTEREST) echo Pinterest;;\n'
    '  TELEGRAM) echo Telegram;; WHATSAPP) echo WhatsApp;; DISCORD) echo Discord;; NETFLIX) echo Netflix;; DISNEY) echo "Disney+";; PRIME) echo "Prime Video";;\n'
    '  TWITCH) echo Twitch;; APPLE) echo "Apple Music/iCloud";; GAMES) echo "Steam/games";; DEV) echo "GitHub/Docker/npm/PyPI";; CUSTOM)')

sub('  any_not_direct ADULT SPOTIFY SCLOUD SNAP CUSTOM && return 0', '  any_not_direct $WIDE_SVCS && return 0')

# Xray config: one rule per newer service, after Google / Instagram / Spotify ... (they win on overlaps)
sub("rule(E['GSN'], target('SNAP'))",
    "rule(E['GSN'], target('SNAP'))\n"
    "geox={}\n"
    "for x in E.get('GEOSVX','').split():\n"
    "    k,c=x.split(':',1); geox.setdefault(k,[]).append(c)\n"
    "for x in E.get('SVXL','').split(';'):\n"
    "    if x.count('|')!=2: continue\n"
    "    k,doms,ips=x.split('|'); ips=ips.split()\n"
    "    if target(k)=={\"outboundTag\":\"direct\"}: continue   # direct = the last rule anyway (fewer rules per connection)\n"
    "    rule(doms+gs(' '.join(geox.get(k,[]))), target(k))\n"
    "    if ips: rules.append(dict({\"type\":\"field\",\"inboundTag\":TP,\"ip\":ips}, **target(k)))")

sub('GSN="$G_SNAP" ', 'GSN="$G_SNAP" GEOSVX="$GEO_SVX" SVXL="$(svx_lists)" ')
sub('is_wide_svc(){', '''svx_lists(){ local k v i; for k in $SVX; do v="G_$k"; i="IP_$k"; printf '%s|%s|%s;' "$k" "${!v}" "${!i}"; done; }   # "KEY|domains|ips;..." for the config builder
is_wide_svc(){''')

# apply: when only the routing rules changed, swap them live (no restart: no connection is cut)
sub('''  if [ "$before" != "$(md5sum 2>/dev/null < "$CONF")" ] || ! systemctl is-active --quiet igproxy-xray; then reload_xray; fi''',
    '''  if ! systemctl is-active --quiet igproxy-xray; then reload_xray
  elif [ "$before" != "$(md5sum 2>/dev/null < "$CONF")" ]; then hot_rules || reload_xray; fi''')

sub('apply_reload(){', r'''hot_rules(){ # the new config differs only in its routing (rules / balancers) -> load them into the running Xray
  [ -s "$CONF.good" ] && [ -z "$NOHOT" ] || return 1
  local f; f=$(mktemp --suffix=.json)
  python3 - "$CONF.good" "$CONF" "$f" <<'PY' || { rm -f "$f"; return 1; }
import json, sys
a, b = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
for k in set(a) | set(b):
    if k != 'routing' and a.get(k) != b.get(k): sys.exit(1)      # inbounds / outbounds / observatory changed: restart
if a.get('routing', {}).get('domainStrategy') != b.get('routing', {}).get('domainStrategy'): sys.exit(1)
json.dump({"routing": b["routing"]}, open(sys.argv[3], "w"))
PY
  if XRAY_LOCATION_ASSET="$DIR" timeout 20 "$XRAY" api adrules -s "127.0.0.1:$API_PORT" -t 10 "$f" >/dev/null 2>&1; then
    rm -f "$f"; cp "$CONF" "$CONF.good" 2>/dev/null; pin_active; log "routes changed live (no router restart)"; return 0; fi
  rm -f "$f"; return 1; }
apply_reload(){''')

# routeset: several services in one go (one apply)
sub('route_cmd(){ # route <service|ALL> <proxy|proxyN|warp|warp6|ipv6|direct>',
    r'''routeset_cmd(){ # routeset SVC=via [SVC=via ...] : several routes, one apply (bulk changes from the panel)
  local x g r rr ok=""
  [ $# -gt 0 ] || die "usage: routeset <service>=<route> ..."
  for x in "$@"; do g=${x%%=*}; g=${g^^}; r=${x#*=}; r=${r,,}
    [[ " $SVCS " == *" $g "* ]] || die "service must be one of: $SVCS"
    case "$r" in proxy|warp|warp6|ipv6|direct) ;; proxy[0-9]*) [[ "$r" =~ ^proxy[1-9][0-9]*$ ]] && [ "${r#proxy}" -le "$(nproxies)" ] || die "there is no $r here";;
      *) die "route must be proxy, proxyN, warp, warp6, ipv6 or direct";; esac
  done
  for x in "$@"; do g=${x%%=*}; g=${g^^}; r=${x#*=}; rr=${r,,}
    if is_wide_svc $g; then case "$rr" in warp6) rr=warp;; ipv6) continue;; esac; fi
    set_route $g $rr; ok="$ok $g=$rr"
  done
  rm -f "$RUN/last_livecc"; apply quiet; warp_ensure; echo "  routes:$ok"
}
route_cmd(){ # route <service|ALL> <proxy|proxyN|warp|warp6|ipv6|direct>''')
sub('  route|routes) if [ $# = 0 ]; then show_routes; else route_cmd "$@"; fi;;',
    '  route|routes) if [ $# = 0 ]; then show_routes; else route_cmd "$@"; fi;;\n  routeset) routeset_cmd "$@";;')
sub('  route <IG|GOOGLE|YTM|ADULT|SPOTIFY|SCLOUD|SNAP|CUSTOM|ALL>', '  route <IG|GOOGLE|YTM|ADULT|SPOTIFY|SCLOUD|SNAP|OPENAI|CLAUDE|...|CUSTOM|ALL>')
sub('(proxyN = only that proxy, e.g. proxy2)', '(proxyN = only that proxy, e.g. proxy2)\n  routeset SVC=route [SVC=route ...]   several services at once (one live reload)')
open(sys.argv[2], 'w', encoding='utf-8', newline='\n').write(src)
print("patched", n, "places")
