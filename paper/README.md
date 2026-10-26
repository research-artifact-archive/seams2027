# Paper and supplement

**Which Winning Continuations Survive One-Way Helper Encodings?**

| Purpose | File |
| --- | --- |
| Read the argument and central complete proof (9 pages including references) | [Main paper](main.pdf) |
| Inspect supporting proofs, case details and evidence history (136 pages) | [Supplement](supplement.pdf) |
| Browse matching sources | [source/](source/) |
| Download matching sources and bundled PDFs | [Source ZIP](source.zip) |
| Check the fixed v71-r10 triplet | [PAPER_MANIFEST.json](PAPER_MANIFEST.json) |

## Reading the argument

The main paper has nine pages in total. Conclusion, Acknowledgments and References flow consecutively on page 9. Its central results and complete proofs are in the main paper.

| Question | Main paper | Supporting supplement |
| --- | --- | --- |
| What can a negative answer justify? | Section I, pp. 1–2, and Fig. 1 distinguish source strict, source-kind, encoded strict, public-action and fixed raw-solver questions. | Opening reader guide, pp. 1–2. |
| Why does an immediate safe response not suffice? | Section II, pp. 2–3, introduces Patrol, its legal route (Fig. 2), release timing (Table I), request/dwell milestones (Table II) and all-response obstruction (Fig. 3). Section IV-A/B, pp. 4–5, closes both the positive policy and negative argument. | S, U.1 and AB.6 give the source, route and export obligations; U.6 records the reduced calculation. |
| What is the exact preservation condition? | Section III, pp. 3–4: Theorem 1 and Corollary 2, both with complete proofs on p. 4. Section IV-C, p. 5: Proposition 3 with complete proof and the two-source-state retained-duty example. | L.6 gives the complete-relations formulation, corrected-guard proof and examples. L.1 gives the retained-duty relational formulation and safety fixed point. |
| Which source-kind witnesses are established? | Section V-A, pp. 5–6, states the all-history requirement and Patrol completion; V-B/C, p. 6, gives Vehicle and Obstacle premises, including the two-phase rank-certificate checks. | AC.5–AC.7 and AD.1–AD.6 distinguish initialized quantifiers, actually reached private memory and off-assumption completion. |
| Which implementation observations support the claims? | Section V-B/C, pp. 6–7: Vehicle loss and Fig. 4; Obstacle's three distinct comparisons in Table III and strict-region counts in Table IV. | Vehicle E/X/AD.3; Obstacle AC–AE; the completed exact-B raw pair is AG. AF preserves the separate earlier false/UNKNOWN protocol. |
| What does the conditioned cohort establish? | Section V-D, p. 7, and Table V retain the 49/9/1 partition and exclude an operational incidence estimate. | J and AB.4–AB.5 give selection, exclusions, certificates and unresolved intersections. |
| How can the result be used or checked? | Section VI, pp. 7–8, gives the query-specific exclusion contract and three saved-evidence checks. Section VII, p. 8, gives common limits and prior work; Section VIII, p. 9, concludes. | Opening guide and evidence index give entry points; the historical directory preserves earlier scope and UNKNOWNs. |

## Three executable case checks

- **Patrol:** follow the [continuation guide](../results/guides/CONTINUATION_EVIDENCE.md) to the positive policy, all-response countercertificate, typed export premises and saved reduced-query records. The executed legal-policy reuse and the proved off-assumption completion have different scopes.
- **Vehicle:** follow the [whole-region guide](../results/guides/VEHICLE188_WHOLE_REGION_EVIDENCE.md) to saved loss membership, initial decisions and target-specific predecessor checks. These checks reuse saved regions and do not independently establish their maximality.
- **Obstacle B:** follow the [positive source certificate and source-kind bridge](../results/guides/V71_R6_POSITIVE_CERTIFICATES_AND_CONTROLS.md), then the [completed same-observer pair](../results/guides/COMPLETED_SAME_OBSERVER_PAIR.md). The source witness, strict-region comparison, public-mode observations and fixed raw pair answer distinct questions.

The two Obstacle guides bind the same source query: `B_NEW_POINT_R2404`, 2,026 bytes, SHA256 `212309df489c3ddc7bf7ec6a750aed2d0da4fb7e26995e5ee3a0405c9897e1d5`, with ENV `obstacle=(3,5), obsWait=true` and SYS `robot=(5,5)`. In the positive-certificate archive, follow `certificates/B.json`, `c1/stages/checker_B/CHECK_RECEIPT.json` and `c1/stages/source_ENV_totality_binding/TOTALITY_BINDING_RECEIPT.json`. In the completed-pair archive, `RESULT_SUMMARY.json` leads to both native results with that same input hash and the helper initially false. The saved comparisons bind the sole typed `0→1` SYS-duty release to the completed false/true pair. This connects a positive source witness to the fixed raw-solver comparison; it establishes neither source-region maximality nor a general source-kind/raw-solver equivalence. Public derivatives retain explicit mappings to the original evidence identities.

The [earlier diagnostic](../results/guides/SAME_SOLVER_DIAGNOSTIC.md) remains false/UNKNOWN. It is not completed retroactively by AG. All checks must be interpreted within their guide's scope: document rebuilding, repository integrity, certificate rechecking, saved-data replay and new scientific execution are separate activities. No fresh-host scientific reproduction or operational gate benefit is claimed by this release.

The PDFs and source ZIP are the frozen v71-r10 triplet. The extracted `source/` tree is an exact mirror of the ZIP, including its README and bundled PDFs. Build instructions are in the ZIP's `README.txt`; document compilation does not rerun experiments.

For case-specific executable checks, follow the [three reader tasks](../README.md#three-reader-tasks): Patrol's maintained-response obligation, Vehicle's lost continuations, and Obstacle's separately scoped source witnesses, strict comparisons, public mode observations and completed raw pair. The [results guide](../results/README.md) connects each to its exact evidence and limitations, including the unfavorable cohort and historical UNKNOWNs.

[Versions](../docs/versions.md) · [Repository](../README.md)

Layout revision 2 changes only endmatter page and column flow. The supplement and scientific evidence are unchanged. Fixed-v1 citations inside the PDFs retain the original evidence release and reading map; all main section and theorem page locations remain the same. This page and the current manifest describe the revised document layout.
