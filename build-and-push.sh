#!/bin/bash

# version of the checked out commit if it is a release tag, otherwise dev
tag=$(git describe --tags --exact-match 2>/dev/null || echo dev)
export DOCKER_BUILDKIT=1
docker buildx build --platform linux/amd64 --build-arg VERSION=$tag -t ghcr.io/g10f/oauth-python-sample:$tag -t ghcr.io/g10f/oauth-python-sample:latest --load .
