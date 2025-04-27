#!/bin/bash
VERSION=2.2.10

sed -i "s/__version__ =.*/__version__ = '${VERSION}'/" apps/client/__init__.py

