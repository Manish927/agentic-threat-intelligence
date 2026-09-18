# GitHub Project Setup and Check-in Plan

The commands below assume the ZIP is extracted to:

`C:\Users\mannu\github_repo\Agentic_Threat_Intelligence`

## Validate before Git initialization

```powershell
cd C:\Users\mannu\github_repo\Agentic_Threat_Intelligence
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
pytest -q
```

## Initialize Git

```powershell
git init
git branch -M main
```

## Recommended check-in sequence

### Check-in 1 — architecture and documentation

```powershell
git add README.md docs pyproject.toml .gitignore .env.example
git commit -m "docs: establish Agentic Threat Intelligence platform architecture"
```

### Check-in 2 — secure communication foundation

```powershell
git add src\agentic_threat_intelligence\communication
git add tests\test_envelope.py tests\test_registry.py tests\test_disclosure.py
git commit -m "feat(communication): add secure typed agent communication foundation"
```

### Check-in 3 — orchestration foundation

```powershell
git add src\agentic_threat_intelligence\agents tests\test_orchestrator.py
git commit -m "feat(orchestration): add specialist agent orchestration foundation"
```

### Check-in 4 — MCP integration boundary

```powershell
git add src\agentic_threat_intelligence\mcp
git commit -m "feat(mcp): add provider-neutral MCP tool integration boundary"
```

### Check-in 5 — model and deterministic policy boundaries

```powershell
git add src\agentic_threat_intelligence\models src\agentic_threat_intelligence\policy
git add tests\test_policy_engine.py
git commit -m "feat(policy): add model abstraction and deterministic policy authority"
```

### Check-in 6 — examples and verification

```powershell
git add examples scripts CONTRIBUTING.md
git commit -m "test: add communication demo and repository verification scripts"
```

## Verify before first push

```powershell
.\scripts\verify.ps1
git status
git log --oneline --decorate -10
```

## Create GitHub repository

Suggested repository name:

`agentic-threat-intelligence`

Suggested description:

`Multi-agent cybersecurity decision platform with secure agent communication, MCP-enabled tool integration, deterministic policy enforcement and human-in-the-loop escalation.`

Create the GitHub repository without generating another README or `.gitignore`.

## Connect and push

Replace `<YOUR_GITHUB_USER>` with your GitHub username:

```powershell
git remote add origin https://github.com/<YOUR_GITHUB_USER>/agentic-threat-intelligence.git
git remote -v
git push -u origin main
```

## Verify synchronization

```powershell
git fetch origin
git status -sb
```

Expected output has `main...origin/main` with no `ahead` or `behind` marker.

## First architecture tag

```powershell
git tag -a v0.1.0 -m "Agentic Threat Intelligence architecture foundation"
git push origin v0.1.0
```

## Suggested future commit messages

- `feat(agent): add message intelligence specialist`
- `feat(agent): add threat intelligence specialist`
- `feat(discovery): add lease-based capability health tracking`
- `feat(mcp): integrate threat intelligence MCP server`
- `feat(evidence): add provenance-aware evidence store`
- `feat(observability): add OpenTelemetry agent tracing`
- `feat(policy): add human-review escalation policy`
- `test(agent): add specialist contract tests`
- `fix(communication): prevent duplicate correlation dispatch`
- `docs(architecture): document agent trust boundaries`
