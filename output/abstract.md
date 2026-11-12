# SCCUR 2026 abstract (P2)

Status: Draft 8 of the P2 abstract (2026-10-08): the second problem (testbed patterns) now has its method and result in one sentence — a host-only rule against source bytes (area under the ROC curve 0.991 vs 0.865) plus the hourly pattern; the effect-size sentence removed; title rewritten in the exemplar title form (was: Fingerprint or Testbed? Integrating the Headerless UNSW-NB15 Files to Separate Attack Behavior from Lab Artifacts)

Generated from `abstract.json` by `abstract_write.py render` — edit abstract.json, then re-render.

## Title (94/200 characters)

Separating Attack Behavior from Testbed Artifacts in the UNSW-NB15 Intrusion Detection Dataset

## Abstract (1478/1500 characters)

Intrusion detection is widely evaluated on UNSW-NB15, a benchmark built in a University of New South Wales lab (its source paper has 3,977 citations); prior analysis found class imbalance and overlap (Zoghi & Serpen, 2023), but inconsistent labels and testbed patterns that can be seen as attack behavior require attention. Its 2,540,047 flows are in four headerless files, with 13 label spellings for 9 families. We constructed a third-normal-form SQLite database from its 49-row definition file, decoding ports and repairing labels. Compared with the raw files, the database contains 9 attack families instead of 13 groups (Fuzzers split 19,195 + 5,051), identifies 312 non-decimal ports, and computes family medians 2.6x faster with 4.1x less memory. Attack flows are clearly smaller and shorter than normal ones, families vary strongly in byte size, and service is moderately related to attacks. However, linking each flow to its source host, we found all attacks are from 4 of 43 hosts; a rule that flags those hosts' flows, a shortcut any trained detector can learn, achieves an area under the ROC curve of 0.991, above source bytes at 0.865, and hourly attack shares (0% to 28.8%) likely follow the testbed schedule. Byte and duration profiles represent attack behavior; host and time features may cause detectors to learn testbed artifacts. Next, scikit-learn and TensorFlow classifiers without those features will be evaluated per family on F1 and area under the curve.

## Keywords

- network intrusion detection
- UNSW-NB15
- data integration
- label cleaning
- effect size

## Track (suggested)

Engineering or Computer Science

## Session type (suggested)

Poster (75 minutes)
