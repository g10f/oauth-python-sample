#!/bin/bash
VERSION=2.3.1

sed -i "s/__version__ =.*/__version__ = '${VERSION}'/" apps/client/__init__.py
sed -i "s/^  tag:.*/  tag: ${VERSION}/" ../dwbn-demos/helmfile/oidc/values.yaml

