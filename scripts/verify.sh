#!/usr/bin/env bash
set -euo pipefail
python -m compileall -q src examples tests
python -m pytest -q
echo "Repository verification complete."
