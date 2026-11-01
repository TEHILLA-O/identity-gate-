# Security controls

The catalogue maps illustrative checks to NIST SP 800-53 families. An ISO/IEC 27001:2022 note is stored as context. Nothing in the report is an ISO certification, a FedRAMP authorization, or a claim that the demonstration implements the full control.

| Id | Intent | Honest result on the seed |
| --- | --- | --- |
| AC-2 | Account lifecycle | Passes when the departed account is disabled in Keycloak |
| AC-2(3) | Deprovisioning | Passes only after a leaver verification succeeds |
| AC-3 | Access enforcement | Passes when Finance returns 401 for an anonymous report read. Unreachable stays not evaluated |
| AC-5 | Separation of duties | Fails while an open conflict exists. Zero conflicts is needs review, not a pass |
| AC-6 | Least privilege | Fails while a privileged role has no approval evidence |
| AU-2 / AU-12 | Logging | Depend on ingested events and an intact chain |
| IG-SVC | Service accounts | Fails while an unapproved service account is active |
| IG-CFG | Configuration | Records realm flags that were actually read |

A missing evidence source stays `not_evaluated`. It is never converted into a pass.

Findings use fixed weights: critical 40, high 25, medium 12, low 5. The score is a sum of matched rules. It is not a probability and it does not label a person as malicious. Findings close when a later evaluation no longer sees the condition, except while a reviewer has marked the item acknowledged, investigating, or accepted. Segregation, failed deprovisioning, and a departed user who is still active downstream cannot be manually marked resolved.

Exports are JSON, CSV, XLSX, and PDF. Each export records the generation time. The PDF states that the organisation is fictional and that the document is not a certification.
