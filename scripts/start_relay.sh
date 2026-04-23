#!/bin/bash
cd "$(dirname "$0")/.."
echo "Starting SOST Relay Node on port ${PORT:-8400}..."
npx ts-node src/relay/http_api.ts
