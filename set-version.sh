#!/bin/bash
VERSION=2.1.7

sed -i "s/__version__ =.*/__version__ = '${VERSION}'/" apps/client/__init__.py

