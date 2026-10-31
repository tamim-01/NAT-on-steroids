#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$root/bin/nat-on-steroids" "$@"
