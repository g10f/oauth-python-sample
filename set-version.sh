#!/bin/bash
VERSION=2.2.6

sed -i "s/__version__ =.*/__version__ = '${VERSION}'/" apps/client/__init__.py

