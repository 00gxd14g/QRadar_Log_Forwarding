#!/bin/bash
# Audit log sonucunu çıkar
if echo "$1" | grep -q "res=success\|success=yes"; then
    echo "success"
else
    echo "failed"
fi
