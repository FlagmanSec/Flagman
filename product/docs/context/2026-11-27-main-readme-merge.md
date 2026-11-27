> Markdown copy of [`2026-11-27-main-readme-merge.docx`](2026-11-27-main-readme-merge.docx),
> generated from the same text, so that it can be read and reviewed in a diff.

# Bringing pull request #2 and the phase 3 branches up to date with main

*Context document for the merge of main’s new README (#10) into the eight open branches, 27 November 2026*

| Item | Details |
|---|---|
| Repository | `FlagmanSec/Flagman` |
| Branches | `phase-1-followups` (pull request #2, into `main`) and the seven `phase-3/…` branches (draft pull requests #3 to #9), each built on the one below it |
| Why | After pull request #10 was merged into `main`, GitHub reported that #2 could no longer be merged: a merge conflict |
| Written by | Claude Code, an AI coding assistant, which opened #2 to #9 and keeps them mergeable |
| This file | `product/docs/context/2026-11-27-main-readme-merge.docx`, with a Markdown copy next to it |

Contents:

1. The short version
2. What changed on main
3. Why GitHub reported a conflict
4. How the conflict was resolved
5. One line of the main README
6. The seven phase 3 branches
7. How it was checked
8. Noticed, but not changed
9. What is left
10. Use of AI

## 1. The short version

- Pull request #10 was merged into `main` on 27 November. The main README now describes Flagman instead of the CS395 project, the CS395 README moved to `RESEARCH.md`, and the install guides get Node.js from NodeSource, because Ubuntu’s own package is too old for the dashboard.
- #2 and #10 had both added a section at the same place in `product/CHANGELOG.md`, so GitHub could not merge #2 by itself.
- `main` was merged into `phase-1-followups`. In the changelog, both sections are kept word for word. Nothing was rewritten and nothing was force-pushed.
- One line of the new main README was updated: its login rule now also mentions servers on the internet, because #2 changes that rule. It uses the same words as `product/README.md`.
- The same merge was then carried up the seven phase 3 branches, each one merged into the next, so every draft pull request still sits on the one below it.
- **No code changed.** On all eight branches, only Markdown files and this document’s two files differ from before.

## 2. What changed on main

Pull request #10, “Main README for Flagman phase 1, with the Ubuntu install”, is commit `f21e614` on `main`. It changed five files:

| File | What #10 did |
|---|---|
| `README.md` | Rewritten. It now describes Flagman phase 1: what it detects, how to install it on Ubuntu, a test on one PC, everyday commands, known limits, what comes next, and the team. |
| `RESEARCH.md` | New. It is the CS395 README, moved. It is identical to the old `README.md` (checked with `git diff`, section 7). |
| `product/CHANGELOG.md` | A new “Fixed” section about the Node.js advice. |
| `product/README.md` | One line: the `sudo apt install … nodejs npm` command before the build commands became a comment that points to `deploy/linux/README.md`. |
| `product/deploy/linux/README.md` | The build steps install Node.js 22 from the NodeSource repository. Ubuntu 24.04’s own `nodejs` is version 18, and the dashboard needs 20.19 or newer. |

## 3. Why GitHub reported a conflict

Git merges two branches by starting from the last commit they share, here `c60543d` (the merge of pull request #1). It then applies the changes of both sides. When both sides changed the same place in the same file, Git cannot know which version to keep, so it stops and asks. That is a merge conflict.

Here, #2 and #10 both added a new section right after the last line of version 0.1.0 in `product/CHANGELOG.md`: #2 added “Changed (phase 1 follow-ups)”, and #10 added “Fixed”. Everything else merged by itself. `product/README.md` was changed on both sides, but on different lines: #2 changed the login row of the table, and #10 changed the first line of the build commands.

## 4. How the conflict was resolved

```text
git checkout phase-1-followups
git merge origin/main      # stops on product/CHANGELOG.md
```

- Both sections are kept, word for word. The follow-ups’ “Changed” section comes first, next to the other “Changed” section of 0.1.0. Main’s “Fixed” section follows.
- This is commit `5e80a11`, a merge commit. Its two parents are the last commit of #2 (`14d4ca4`) and `main` (`f21e614`).
- Why a merge and not a rebase: a rebase would rewrite the branch’s commits, and pushing them would need a force-push, which the team’s rules forbid. A merge only adds a commit, and the history stays as everyone has it.

## 5. One line of the main README

The new main README was written on `main`, which does not have #2 yet, so its table describes the login rule as it was before #2. Once #2 is merged, that line would be wrong. Commit `348a99b` changes this one table row:

|  | The “Default rule” column of the Login attempts row |
|---|---|
| Before | 10 or more connections to a login port of a device in your network within 60 s that were refused or closed within 30 s |
| After | the same, followed by: “; 30 or more for a server on the internet (a device of yours that guesses passwords elsewhere may be infected)” |

- Why: #2 makes Flagman report password guessing against servers on the internet too ([ADR 0011](../adr/0011-watch-logins-to-internet-servers.md)). The defaults are in `product/core/crates/flagman-core/src/detect/config.rs`: a 60 s window, 10 attempts inside the home (`min_attempts`), 30 for an internet server (`outbound_min_attempts`), and `local_targets_only = false`.
- `product/README.md` on #2 already says this, with the same words. The two tables now agree.
- The README describes a new installation. Existing installations keep `local_targets_only = true` from their own `/etc/flagman/flagman.toml` until someone changes it, as the changelog of #2 says.
- This is the only file outside `product/` that this push changes.

## 6. The seven phase 3 branches

Each draft pull request is built on the branch below it. After `phase-1-followups` moved, each branch was merged into the next one, from the bottom up:

| Branch | Pull request | Merged into it |
|---|---|---|
| `phase-1-followups` | #2, into `main` | `main` (this push’s merge, section 4) |
| `phase-3/01-features` | #3 (draft) | `phase-1-followups` |
| `phase-3/02-extract` | #4 (draft) | `phase-3/01-features` |
| `phase-3/03-ml-data` | #5 (draft) | `phase-3/02-extract` |
| `phase-3/04-models` | #6 (draft) | `phase-3/03-ml-data` |
| `phase-3/05-evaluation` | #7 (draft) | `phase-3/04-models` |
| `phase-3/06-suricata` | #8 (draft) | `phase-3/05-evaluation` |
| `phase-3/07-export-runbook` | #9 (draft) | `phase-3/06-suricata` |

- Before the real merges, a dry run with `git merge-tree`, which merges without changing any branch, showed that main’s changes and the README line merge into all seven branches without a conflict. The phase 3 branches add their changelog entries in a new section at the top of the file, far from main’s section at the end of 0.1.0.
- The one conflict on each branch is in `product/docs/context/README.md`, the index of these documents. Every branch adds its own row at the end of the table, and this push adds one too. Each time, the branch’s own rows are kept and this document’s row goes last, since the index lists the newest last.
- Without these merges, #3 would conflict with `phase-1-followups` over this document’s row in the index, and fixing #3 alone would move the same conflict to #4, and so on up the stack. Merging all seven also gives every branch main’s new README.

## 7. How it was checked

| Check | Result |
|---|---|
| `git diff --stat` between each branch’s old and new last commit | On all eight branches, only Markdown files and this document changed: `README.md`, `RESEARCH.md`, `product/CHANGELOG.md`, `product/README.md`, `product/deploy/linux/README.md` and `product/docs/context/`. No Rust, Python, Svelte or test file. |
| `git diff c60543d:README.md origin/main:RESEARCH.md` | Empty: `RESEARCH.md` is the old CS395 README, unchanged. |
| `git diff origin/main <branch> -- src notebooks results requirements.txt` | Empty on every branch: the CS395 files are untouched. |
| A search for leftover conflict markers (`<<<<<<<`, `>>>>>>>`) | None on any branch. |
| The README line against the code | The numbers are the defaults in `config.rs` (section 5). |

The tests were not run again on this machine, because no code changed since they last passed: on #9, for example, 212 Python tests passed in CI. CI runs again on every push, and its results show on each pull request.

## 8. Noticed, but not changed

- [ADR 0002](../adr/0002-product-folder-in-research-repo.md) says that the only product file outside `product/` is the CI workflow, and that the research README stays as it is. Since #10, the main README describes Flagman and the research README is `RESEARCH.md`. The team may want to update the ADR; a decision record is the team’s to change.
- The phase 1 context document of 26 November still shows the old `apt install … nodejs npm` line. A context document records one push, so it stays as it was. The install guides that people follow are correct.
- Earlier documents say that #3 to #9 will be rebased on `main` when phase 3 starts. This push merged instead, for the reason in section 4.

## 9. What is left

1. The team reviews and merges #2 into `main`, then #3 to #9 in order, as before.
2. If `main` changes again before that, the same steps bring the branches up to date. Each command merges the branch below into the one above; when Git stops on a conflict, keep both sides and commit.

```text
git checkout phase-1-followups && git merge origin/main
git checkout phase-3/01-features && git merge phase-1-followups
git checkout phase-3/02-extract && git merge phase-3/01-features
# … and so on, up to:
git checkout phase-3/07-export-runbook && git merge phase-3/06-suricata
git push origin phase-1-followups phase-3/01-features …   # no --force
```

## 10. Use of AI

Claude Code, Anthropic’s AI coding assistant, did the merges, chose how to resolve the conflicts, changed the README line and wrote this document, in its cloud session, after GitHub’s notice about #2. Every statement here comes from `git` output or from the files named. The team reviews and merges; the AI never merges.
