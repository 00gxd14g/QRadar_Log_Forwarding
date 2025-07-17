#!/bin/bash
# Audit log tipini çıkar
echo "$1" | grep -oP 'type=\K\w+' | head -1
