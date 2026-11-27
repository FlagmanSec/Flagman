# 0014. Alerts from two scores, a conformal false-alarm budget, and temperature scaling

Status: proposed (phase 3 branch; accepted when phase 3 starts)
Date: 2026-11-27

## Context

Phase 3 adds machine learning detectors on the per-flow features
([ADR 0012](0012-features-computed-inside-the-flow-table.md)). Three needs
shape how they raise alerts:

- **A false-alarm rate the user chooses.** In CS395, 39.6% of normal flows
  raised an alarm, mostly through a lab shortcut (see the glossary). A
  home network can bear very few, so the rate must be a setting, α, and
  the thresholds must be set on normal traffic kept aside, not on the
  training flows (which the models have seen).
- **Attacks no dataset labelled.** A classifier only knows the classes it
  was trained on; a new attack must still raise an alert.
- **Splits by day or session, never at random.** Flows of one capture are
  related, so the calibration flows are whole files. A day of a public
  dataset often holds some attack classes only.

## Decision

- **Classifier**: LightGBM on the training files. Its probabilities are
  calibrated by **temperature scaling** on the calibration files: the raw
  scores are divided by one number T before the softmax, T chosen for the
  lowest negative log-likelihood. Source: Guo et al., "On Calibration of
  Modern Neural Networks", ICML 2017, PMLR 70:1321-1330, section 4.2
  ("a single scalar parameter T > 0 for all classes", "optimized with
  respect to NLL on the validation set", "does not affect the model's
  accuracy").
- **Anomaly detector**: an Isolation Forest trained on the training files'
  normal flows only.
- **Two scores, one threshold each**: suspicion = 1 − P(normal), and the
  anomaly score. Each threshold is the split conformal threshold at α/2:
  the ⌈(n+1)(1−α/2)⌉-th smallest score of the n normal calibration flows
  (Angelopoulos and Bates, arXiv:2107.07511 v6, section 1.1). A flow
  raises an alert when either score is above its threshold. If new normal
  traffic is exchangeable with the calibration traffic, each threshold is
  passed by a normal flow with probability at most α/2, so an alert on a
  normal flow has probability at most α (the union bound), on average over
  calibration sets.
- **Open-set rule**: an alert gets the classifier's top class when that
  class is an attack and its probability is at least `min_confidence`
  (0.5); otherwise it is `unknown_suspicious`.
- **Too few calibration flows**: when n is too small for α/2, the
  threshold is infinite (no alert) and training warns. A budget α needs at
  least 2/α − 1 normal calibration flows: 199 for α = 0.01, 1,999 for
  α = 0.001.
- **Drift monitor**: on a recent window, a binomial test of the alert rate
  against α, a Kolmogorov-Smirnov test of the anomaly scores against the
  calibration ones, and the population stability index of each feature.
- **Bundles**: the models in a joblib file whose SHA-256 is recorded in
  `bundle.json`, with the schema, flow table settings, training data
  checksums, thresholds and library versions. A changed file is refused.

## Consequences

- The budget is a promise about average behaviour on exchangeable traffic,
  never a guarantee for a real network: the documents never say
  "guaranteed", and the drift monitor says when the traffic has moved.
  The evaluation (next pull request) compares the observed false-alarm
  rate with the configured one.
- The union bound is cautious: both scores often flag the same flows, so
  the observed rate can be well below α.
- An attack never seen in training raises alerts, but it can get the name
  of a known class with high confidence (a test with made-up floods shows
  it: they come out as "scan"). Leave-one-attack-type-out evaluation
  measures how often.
- Temperature scaling never changes the top class and cannot fix a
  calibration error of one class only.
- Loading a joblib file runs code: bundles are only loaded from this
  project's own `results/`, after the checksum check.

## Alternatives considered

- **Calibration per class** (Platt scaling, isotonic regression, through
  scikit-learn's `CalibratedClassifierCV`): more flexible, but it needs
  every class in the calibration files; scikit-learn 1.9.1 takes its
  classes from the calibration labels and failed on the lab files, whose
  calibration file has no scan.
- **A fixed probability threshold** (alert when P(attack) > 0.5): no
  control of the false-alarm rate on the network being watched; the CS395
  problem.
- **Thresholds set on the training flows**: the models have seen them, so
  their scores look better than on new traffic and false alarms come out
  above the budget.
- **One combined score with one threshold at α**: no union bound needed,
  but the two scores have different scales, and two thresholds keep each
  alert explainable ("the classifier said so" or "unlike normal traffic").
- **Random calibration rows**: near-copies of training flows would land in
  the calibration set and make the thresholds too low.
