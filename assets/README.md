# Embedded assets

This directory is populated by `build.sh` and is **not** fully committed to git:

| File | Produced by | In git? |
|---|---|---|
| `tp-agent-amd64`, `tp-agent-arm64` | `build.sh` compiles `./cmd/tp-agent` | no |
| `golden-gre-relay-amd64` | `build.sh` compiles `third_party/golden-gre/*.c` with gcc | no |
| `backhaul_premium-amd64` | **you** upload it in the panel (Settings → Helper binaries) | no |

`build.sh` creates the two generated binaries before `go build`, so the single
panel binary ends up with them embedded. The Backhaul Premium core is closed
source and is never bundled or downloaded — upload it once from the web panel and
the panel stores it in its data dir and pushes it to hosts over the agent/SSH.
