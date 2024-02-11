#!/bin/bash

tag=$(python apps/version.py)
export DOCKER_BUILDKIT=1
docker buildx build --platform linux/amd64 -t ghcr.io/g10f/oauth-python-sample:$tag -t ghcr.io/g10f/oauth-python-sample:latest --load .
