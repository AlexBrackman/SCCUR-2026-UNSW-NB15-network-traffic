# P2 storyline — the argument the abstract tells

The single home of the study's story. `abstract-writer` writes sentences from it; `abstract_check.py check`
fails while a section below is empty; the logic test grades readers against Surface, Hidden and Conclusion.
Change the story here first, then the abstract. Every number names its source file.

Flow locked by the instructor on 2026-11-10: the surface looks usable but does not work, so the data was
analyzed, rebuilt as a database, and moved into a Python DataFrame. Steps 1 and 2 of Method carry the claim.

## Topic
UNSW-NB15 (NB15 below) looks ready for intrusion-detection analysis but cannot be analyzed correctly as
delivered; does rebuilding it as a database and analyzing it as a DataFrame make the analysis work, and what
does that analysis then show?

## Surface
NB15 is a widely used benchmark (its source paper has 3,977 citations; references/background/
moustafa2015.json); detectors trained on it report high scores, and its files look ready to use.

## Hidden
- The four raw files have no header; column names and types live in a separate 49-row definition file
  (ResearchPlan.md).
- The raw files carry 13 label spellings for 9 attack families, so a count on the raw files reports 13
  groups (Fuzzers split 19,195 + 5,051), and 312 port values are not decimal (benefits.md).
- Once cleaned, all attack flows come from 4 of 43 source hosts (results.md H4); the source host alone
  separates attacks with an area under the ROC curve of 0.991, above the behavior feature source bytes
  (0.865) (results.md H6).
- The hourly attack share ranges from 0% to 28.8% (results.md H5), likely the traffic generator's schedule.

## Method
1. Raw files -> database (the main claim). The raw files cannot be analyzed correctly, so they were rebuilt
   as a third-normal-form SQLite database from the 49-row definition file: cleaning (13 label spellings ->
   9 families, hexadecimal ports decoded), integrity (0 foreign-key violations, label and family agree on
   every row; verify_output.txt) and normalization (host, service, protocol and family tables; each flow
   linked to its host). Evidence: the correctness and integrity rows of benefits.md.
2. Database -> Python DataFrame (the main claim). One SQL join pulls only the 8 columns a test needs, not
   the 49 raw columns, into pandas for efficient analysis and visualization: the same question (H2) takes
   5.8 s instead of 15.0 s (2.6x faster) and 483 MB instead of 1,980 MB (4.1x less memory) (benefits.md).
3. Statistical analysis, each model with its principle:
   - Bytes and duration are heavy-tailed (ResearchPlan.md section 4; median source bytes attack 114 vs
     normal 1,684, results.md H1a), so mean-based tests that assume normality (t-test, ANOVA) are replaced
     by rank-based tests: Mann-Whitney U for two groups (H1), Kruskal-Wallis for nine families (H2).
   - Service and hour are categories, so attack rates are compared with the chi-square test of
     independence (H3, H5).
   - With 2,540,047 flows every p-value is below 0.001, so each result is judged by its effect size:
     rank-biserial r, epsilon-squared, Cramér's V.
   - Concentration of attacks across hosts is measured with the Gini coefficient and the top-3 share (H4).
   - The area under the ROC curve compares how well one feature separates attack from normal flows on one
     scale (H6; Fawcett 2006).

## Conclusion
NB15 cannot be analyzed correctly as delivered; a third-normal-form database and a DataFrame drawn from it
make the analysis correct and efficient. That analysis shows that byte and duration profiles differ between
attacks and normal traffic, while host and time features act as testbed shortcuts; detectors trained with
them may learn the lab rather than the attacks.

## Limits
- The schedule explanation of the hourly pattern is inferred, not documented by the dataset authors.
- Byte and duration profiles may also carry testbed effects (outside review, 2026-10-07).
- The host rule uses attacking hosts taken from the same labels — exactly what a trained model could learn.
- Time and memory are from one recorded run (benefits.md).
- No formal normality test is run in src/analysis.py; the heavy tails are read from the medians and the
  figures.

## Decisions
| Date | Decision | Reason |
|---|---|---|
| 2026-10-07 | First sentence locked, then reordered so the purpose precedes the dataset name | instructor |
| 2026-10-07 | Zoghi & Serpen cited by the journal year 2023 | published version |
| 2026-10-07 | H6 host shortcut added as the proof of the second problem | proves the claim with a number |
| 2026-10-07 | Draft 4 approved and tagged `abstract-draft4`; drafts 5-6 for discussion | — |
| 2026-10-08 | Draft 7: the testbed problem gets its method and result in one sentence (host-only rule vs source bytes, area under the ROC curve 0.991 vs 0.865, hourly 0%-28.8%); effect-size sentence dropped | the second problem had a result but no method in draft 6 (instructor) |
| 2026-10-08 | ROC used without expansion | standard term (Fawcett 2006 cited 22,132 times; 160,438 works name 'ROC curve'); added to the checker's allow list |
| 2026-11-10 | Flow re-locked: the raw files fail -> database (main claim 1) -> DataFrame (main claim 2) -> statistics, each model with its principle; Surface and Hidden kept; the host shortcut becomes a result | instructor |
| 2026-11-10 | Poster guide built from this flow, one slide per section (plan/poster_guide.json) | instructor |
