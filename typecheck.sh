#!/usr/bin/env bash

# unfortunately pyinotify is not type annotated ;(
# MYPYPATH=/usr/lib/python3/dist-packages

mypy --ignore-missing-imports ssh_copypasta.py
