#!/bin/sh
# Entrypoint for the bundled garage + panel image.
set -e

GARAGE_RPC_SECRET="${GARAGE_RPC_SECRET:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export GARAGE_RPC_SECRET

# Render the runtime config: random RPC secret unless one is provided.
cat > /etc/garage.toml <<EOF
metadata_dir = "/data/garage-meta"
data_dir = "/data/garage-data"

replication_factor = 1
consistency_mode = "consistent"
rpc_bind_addr = "[::]:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "${GARAGE_RPC_SECRET}"

s3_api = {
    s3_region = "${S3_REGION:-us-east-1}",
    api_bind_addr = "[::]:3900"
}

s3_web = {
    bind_addr = "[::]:3902",
    root_domain = "null",
    index = "index.html"
}

admin = {
    api_bind_addr = "[::]:3903"
}
EOF

mkdir -p /data/garage-meta /data/garage-data

echo "[entrypoint] starting Garage (state in /data/garage-meta)"
/usr/local/bin/garage -c /etc/garage.toml server &
GARAGE_PID=$!

cleanup() {
  kill "$GARAGE_PID" 2>/dev/null || true
}
trap cleanup INT TERM

# Wait briefly for the admin API so the panel's first overview succeeds.
i=0
until curl -fsS -o /dev/null http://127.0.0.1:3903/v2/GetClusterStatus \
    -H "Authorization: Bearer ${GARAGE_ADMIN_TOKEN:-}" 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then break; fi
  sleep 0.5
done

echo "[entrypoint] starting admin panel on :${PANEL_PORT:-8088}"
cd /app
python -u garage_panel.py &
PANEL_PID=$!
wait "$PANEL_PID"
