# CLAUDE.md - go-certkit

Working agreement for this repository. It was scaffolded from `Bugs5382/project-template`;
the governance below is shared across all repos created that way.

## Enforced by hooks (run `bash .claude/hooks/install.sh` once per clone)

- Conventional Commits on commits, issue titles, and PR titles.
- No AI tells in commits/issues/PRs/comments/source; no emoji in source or commit messages (emoji
  are allowed in Markdown docs and CI workflow files).
- Pre-push: the ecosystem's format/lint/test gate must pass (Go: gofmt/vet/golangci-lint/test).

## Conventions

- Branching: never commit to `main`. Work on a feature/working branch; open a PR.
- Commits: Conventional Commits (`type(scope): description`). The operator (@Bugs5382) is the
  author of record on every commit.
- Voice: human-authored. No attribution trailers (`Co-Authored-By`, `Generated with`), no robot
  glyphs/emoji, no session framing.
- Local design notes live in a non-tracked `plan/` folder; delete a note when its work is done.
- GitHub Actions: a job id must be a plain identifier (a letter or `_`, then alphanumerics/`-`/`_`);
  put emoji and display text in the job's `name:`, never the job key. The Actionlint check
  (`.github/workflows/action-lint.yaml`) enforces this, so a malformed workflow fails at PR time
  instead of silently at startup on `main`.

## Engineering discipline

- Root-cause before fixing: confirm the actual cause with evidence before changing code; do not
  patch symptoms.
- Map every reference before removing a feature: trace its wiring across the tree first, preserve
  adjacent behavior that only looks related, and defer-and-flag an entangled piece rather than
  guessing it.
- Verify with evidence, not assertions: run the real check for what changed (lint, tests,
  `actionlint` for workflows) before calling it done. Green CI is necessary, not sufficient.
- One concern per branch/PR, even tiny ones -- it keeps reviews and the drafted changelog clean.
- When PRs interact, state an explicit merge ORDER rather than opening them and walking away:
  anything a *tag* triggers needs its inputs on `main` first; a new *gate* (check) needs the
  violations it catches fixed first; a workflow that builds from committed content needs that
  content merged first.
- Semver framing: `breaking` only means breaking against a *released* version; removing something
  that was never shipped is not a breaking change.

## Workflow

Issue (from a template; free-form issues are disabled) -> for sequential / multi-step work, a parent
issue with ordered **sub-issues** -> put it on the active **milestone** -> branch
`<type>/<issue#>-<slug>` -> code (comments cite the issue) -> PR with a Conventional Commit title
(the autolabeler sets the category label from the title), the template body, and a **closing
summary** before merge -> **squash** merge. The operator (@Bugs5382) is the assignee.

On merge, release-drafter drafts the next notes by label -- **nothing tags automatically**. When the
first push to main resolves the version, rename the milestone to that version.

Keep public artifacts (issues, PRs, commit messages) free of references to local-only design notes.

## Releasing

On every push to `main` the **Release Drafter** workflow
(`.github/workflows/job-release-drafter.yaml`) runs and anticipates the next version by aggregating
the merged PRs' categorizing labels into a draft release. **Nothing tags automatically.** The
maintainer publishes the GitHub Release by hand, which creates the `vX.Y.Z` tag with the finalized
notes. The **first release is `v1.0.0` by hand** -- release-drafter would otherwise draft `v0.1.0`
on the first run.
