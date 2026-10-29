#!/usr/bin/env bash
# The proofs-on lightnet that the lightnet tests run against (#33, and later #35, #36, #16).
# One container, reused across runs:  lightnet.sh up | down | status
set -euo pipefail

IMAGE=o1labs/mina-local-network:4.0.2-devnet
NAME=zk-toon-lightnet
GRAPHQL=http://127.0.0.1:8080/graphql

synced() {
  curl -fsS -H 'content-type: application/json' -d '{"query":"{ syncStatus }"}' "$GRAPHQL" 2>/dev/null \
    | grep -q '"SYNCED"'
}

case "${1:-}" in
  up)
    if ! docker container inspect "$NAME" >/dev/null 2>&1; then
      # PROOF_LEVEL=full: the chain checks every proof. A proofs-off chain accepts updates the circuit
      # forbids (connector#1554), so it would not answer what these tests ask.
      docker run -d --name "$NAME" \
        -e NETWORK_TYPE=single-node -e PROOF_LEVEL=full -e LOG_LEVEL=Info \
        -p 127.0.0.1:8080:8080 -p 127.0.0.1:8181:8181 -p 127.0.0.1:8282:8282 \
        "$IMAGE" >/dev/null
    elif [ "$(docker container inspect -f '{{.State.Running}}' "$NAME")" != true ]; then
      docker start "$NAME" >/dev/null
    fi
    echo "waiting for $NAME to sync (a fresh start takes a few minutes)..."
    for _ in $(seq 1 120); do
      if synced; then echo "$NAME is synced: $GRAPHQL"; exit 0; fi
      sleep 10
    done
    echo "$NAME did not sync within 20 minutes; see: docker logs $NAME" >&2
    exit 1
    ;;
  down)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    ;;
  status)
    if synced; then echo synced; else echo "not synced"; exit 1; fi
    ;;
  *)
    echo "usage: $0 up | down | status" >&2
    exit 2
    ;;
esac
