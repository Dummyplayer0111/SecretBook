# Final combined request dataset

The combined file is final_dataset.csv. train.csv, validation.csv and test.csv are
exact subsets selected by its split column.

| Partition | Normal | Attack/anomaly | Total |
| --- | ---: | ---: | ---: |
| Training | 30,090 | 26,332 | 56,422 |
| Validation | 4,736 | 5,286 | 10,022 |
| Test | 4,482 | 5,397 | 9,879 |
| Total | 39,308 | 37,015 | 76,323 |

Original inputs: SQLiV3.csv (30,919 rows), XSS_dataset.csv (13,686), and
csic_database.csv (61,065). Source files are preserved.

## Construction

build_dataset.py resolves input/output paths from the project directory.
It uses Sentence/Label for SQLi/XSS and URL/content/classification for CSIC.
Label-bearing metadata, cookies and headers are excluded from features.
SQLi/XSS payloads of both classes receive the same search-query wrapper.

Shared normalization uses NFKC, up to two HTML/URL decoding passes, NUL escape
markers, whitespace folding and lowercase. Removing 310 invalid/missing rows,
2 over-limit inputs, 6,404 rows with conflicting normalized labels and 32,541
additional duplicates leaves 66,413 source-derived inputs.

Numeric/hex/wrapper grouping and 20 stratified group folds (seed 42) produce
46,512 source training, 10,022 validation and 9,879 test examples, approximately
70/15/15. Training alone receives 6,910 benign deployment examples plus 3,000
variants of 1,500 training attacks. Final proportions therefore differ from 70/15/15.

## Columns

- text: normalized input consumed by the model.
- label: 0 normal; 1 attack/anomaly (CSIC includes invalid non-malicious inputs).
- source, source_row: retained source representative and its original row index;
  deployment identifies added training examples.
- provenance: source:row entries for collapsed duplicates, or a parent sample ID
  for attack augmentation.
- sample_id: SHA-256 of normalized text.
- group_id: identifier used to prevent grouped variants crossing partitions.
- split: train, validation or test.
- augmentation: none or deployment.
- encoding_id: hash of complete character-index sequence under training vocabulary.

vocabulary.pkl contains 116 training-only characters (indices 2..117); padding is 0,
unknown is 1. Inputs use overlapping 256-character windows at stride 192, covering
all normalized characters up to the 4,096-character limit.

manifest.json records counts, source/final hashes, and overlap checks.
excluded_rows.csv preserves normalized conflicting/over-limit inputs. Original
source CSVs preserve invalid/missing records counted in the manifest.

## Evaluation limits

There are no shared groups or identical complete encoded inputs across partitions.
This does not exclude every semantic family overlap. Conflicting-label removal
simplifies the task relative to unfiltered traffic.

The source-only model was tested, then deployment augmentation was added after a
development smoke failure. Test/validation membership stayed fixed, and final
checkpoint/threshold selection used validation only. The test is consequently a
reused holdout. Smoke examples overlap development patterns and are not independent
test evidence. No labels were randomly flipped.

Rebuild with build_dataset.py from the project root. verify_artifacts.py replays
fold assignments, checks CSV equality and vocabulary provenance, and verifies saved
model predictions. Both commands use the separate Python 3.10 training environment.


## Published research snapshot

This is the frozen combined training/validation/reused-test dataset used by the
historical CNN described in the paper. It is not the separate 50,116-request
ECML/PKDD external evaluation dataset or the later synthetic application benchmarks.
The external ECML archive and excluded rows are not distributed in this snapshot.

Upstream versions and redistribution permissions for the supplied SQLi/XSS exports
and CSIC conversion remain unverified. No new license is granted for third-party
content; this repository does not establish that it is public domain or CC BY.
Consult the original data providers before reuse or redistribution.

Source data can contain SQL injection/XSS examples. Treat the text as inert
research data; do not execute payloads. vocabulary.pkl is a Python pickle: load
only trusted copies. SHA256SUMS records the exact published file hashes.

This GitHub snapshot does not by itself establish compliance with the journal's
recognized-repository and open-data licensing requirements.
