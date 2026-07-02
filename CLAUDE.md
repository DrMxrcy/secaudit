<!-- roadmap:rules:start -->
## Roadmap tracking
This project tracks work in `ROADMAP.md` via the **roadmap** skill (`/roadmap:*` commands).
- At the start of a work session, run `/roadmap:status` (or read `ROADMAP.md`) to see current progress before continuing.
- New features or found bugs become roadmap items via `/roadmap:plan` before coding; park stray ideas in the Idea Incubator — nothing is built off-roadmap.
- No functional code without an active plan in `.roadmap/plans/`. Work one checklist item at a time; do not multitask across features/bugs.
- When building an item, follow its linked Spec / Detailed plan as the authoritative how-to (the checklist is just the tracker).
- Mark a step done only after its build/tests pass, and commit the code + roadmap update together; if work was done outside the commands, run `/roadmap:catchup` to reconcile.
- Update status only through the roadmap CLI / `/roadmap:done`; never hand-edit `ROADMAP.md`.
<!-- roadmap:rules:end -->
