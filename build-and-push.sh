#!/bin/bash

tag=$(python apps/version.py)
export DOCKER_BUILDKIT=1
docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/g10f/oauth-python-sample:$version -t ghcr.io/g10f/oauth-python-sample:latest --push .
