#!/bin/bash

tag=$(python apps/version.py)

export DOCKER_BUILDKIT=1
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 -t g10f/oauth-python-sample:$version -t g10f/oauth-python-sample:latest --push .
