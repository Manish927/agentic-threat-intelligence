$ErrorActionPreference = "Stop"
python -m compileall -q src examples tests
python -m pytest -q
Write-Host "Repository verification complete."
