---
id: 24
title: Extend data-access, supply-chain and logging-monitoring for Python
type: feature
version: 3.5.0
status: done
created: 2026-08-24
---

# Plan 24: Extend data-access, supply-chain and logging-monitoring for Python
> Type: feature · Target: v3.5.0

## 🎯 Target Scope & Boundaries

Extend three existing skills so Python sits **beside** its JS counterpart rather than in a
parallel silo. Deliberate structural choice: a reader auditing deserialization should find both
languages in one place.

**Out of scope:** framework-shaped Python gaps (plan 22).

## 🏗️ Architectural Blueprint

- **`logging-monitoring`** — pickle / PyYAML / jsonpickle in §4, and `shell=True` / `eval` /
  `exec` in §5. Three verified details change what you grep for: `safe_load` *and* `FullLoader`
  both block the payload; bare `yaml.load(data)` is a `TypeError` in PyYAML ≥ 6, so the classic
  advice is stale; and **`jsonpickle.decode(..., safe=True)` does not make jsonpickle safe** — a
  `py/reduce` payload executes under `safe=True` and the flag's name actively misleads.
- **`data-access`** — SQLAlchemy `text()` f-string injection plus the identifier-binding trap that
  causes it, and Pydantic mass assignment. Nuance: **Pydantic already ignores undeclared fields**,
  so the Python risk is a privileged field *declared* on the model, not a spread operator.
- **`supply-chain`** — PyPI lock files and hash pinning, `--extra-index-url` dependency confusion
  quoted verbatim from pip's own docs, and `setup.py` as the install hook with no npm equivalent
  mitigation (`--only-binary :all:`).

## ✅ Acceptance

- **Passes when:** all three descriptions mention Python so the skills fire on a Python repo.
- **Fails if:** a Python claim contradicts observed behaviour — each was executed, not assumed.

## 🚶 Step-by-Step Checklist

- [x] Step 1: Add Python deserialization and command-injection to `logging-monitoring`
- [x] Step 2: Add SQLAlchemy and Pydantic to `data-access`
- [x] Step 3: Add PyPI supply-chain material to `supply-chain`
- [x] Step 4: Widen all three descriptions and add sources
