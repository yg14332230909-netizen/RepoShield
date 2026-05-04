#!/usr/bin/env bash
set -euo pipefail
reposhield bench --sample "$(cd "$(dirname "$0")/.." && pwd)"
