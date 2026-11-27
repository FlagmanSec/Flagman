# Context documents

One document per push, explaining in detail what was done, why, how it
works and how it was checked, for readers who will not read the code.
Seraj asked for one with every push. Each comes as a Word file and a
Markdown copy with the same content, which can be read on GitHub and
reviewed in a diff. Newest last.

| Date | Word | Markdown | Covers |
|---|---|---|---|
| 2026-11-26 | [2026-11-26-linux-pro-phase-1.docx](2026-11-26-linux-pro-phase-1.docx) | [2026-11-26-linux-pro-phase-1.md](2026-11-26-linux-pro-phase-1.md) | Phase 1, Linux Pro: the sensor, the dashboard, the tests and the documentation, as first pushed |
| 2026-11-26 | [2026-11-26-review-fixes.docx](2026-11-26-review-fixes.docx) | [2026-11-26-review-fixes.md](2026-11-26-review-fixes.md) | The fixes after Seraj's review of phase 1, and the plan for phase 2 |
| 2026-11-26 | [2026-11-26-phase-1-followups.docx](2026-11-26-phase-1-followups.docx) | [2026-11-26-phase-1-followups.md](2026-11-26-phase-1-followups.md) | The three phase 1 follow-ups: login attempts on internet servers, `ignore_logins`, and the flood limit |
| 2026-11-26 | [2026-11-26-phase-3-features.docx](2026-11-26-phase-3-features.docx) | [2026-11-26-phase-3-features.md](2026-11-26-phase-3-features.md) | Phase 3 toolkit, draft pull request 1: per-flow features computed inside the flow table |
| 2026-11-27 | [2026-11-27-phase-3-extract.docx](2026-11-27-phase-3-extract.docx) | [2026-11-27-phase-3-extract.md](2026-11-27-phase-3-extract.md) | Phase 3 toolkit, draft pull request 2: `flagmand extract` to Parquet behind an off-by-default feature, byte-identical output, the parity test in the phase 2 plan |
| 2026-11-27 | [2026-11-27-phase-3-ml-data.docx](2026-11-27-phase-3-ml-data.docx) | [2026-11-27-phase-3-ml-data.md](2026-11-27-phase-3-ml-data.md) | Phase 3 toolkit, draft pull request 3: the Python pipeline in `product/ml`, labelling flows from dataset ground truth, downloads with checksums, and what is verified about each dataset |
| 2026-11-27 | [2026-11-27-phase-3-models.docx](2026-11-27-phase-3-models.docx) | [2026-11-27-phase-3-models.md](2026-11-27-phase-3-models.md) | Phase 3 toolkit, draft pull request 4: the models (calibrated LightGBM, Isolation Forest, the conformal false-alarm budget, the open-set decision, the drift monitor) and the shortcut audit |
| 2026-11-27 | [2026-11-27-phase-3-evaluation.docx](2026-11-27-phase-3-evaluation.docx) | [2026-11-27-phase-3-evaluation.md](2026-11-27-phase-3-evaluation.md) | Phase 3 toolkit, draft pull request 5: the evaluation harness (plans, folds, leave-one-attack-type-out, cross-dataset holdouts, metrics, paired tests) and reports written only from results files |
| 2026-11-27 | [2026-11-27-phase-3-suricata.docx](2026-11-27-phase-3-suricata.docx) | [2026-11-27-phase-3-suricata.md](2026-11-27-phase-3-suricata.md) | Phase 3 toolkit, draft pull request 6: the Suricata comparison (running `suricata -r`, matching its EVE alerts to flows, Suricata scored in the evaluation) and the EVE test files recorded on the lab captures |
| 2026-11-27 | [2026-11-27-main-readme-merge.docx](2026-11-27-main-readme-merge.docx) | [2026-11-27-main-readme-merge.md](2026-11-27-main-readme-merge.md) | Bringing pull request #2 and the seven phase 3 branches up to date with `main` after its new README (#10): the changelog conflict, one line of the main README, and the merges up the stack |
