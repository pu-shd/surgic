#!/bin/zsh
# Build and run the containerized test suite (network disabled inside the container).
set -euo pipefail
cd "${0:A:h}/.."

if command -v docker-compose >/dev/null 2>&1; then
  docker-compose build tests
  docker-compose run --rm tests "$@"
else
  print -u2 "docker-compose not found; falling back to docker build/run with --network none"
  docker build -f docker/Dockerfile.test -t surgic-tests:latest .
  docker run --rm --network none --tmpfs /tmp:exec surgic-tests:latest "$@"
fi
