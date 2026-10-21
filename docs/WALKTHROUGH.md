# Understand the project

## 1. Input: a JSON audit log

CloudTrail records actions in AWS. Each sample event answers: who acted (`userIdentity`), what happened (`eventName`), when (`eventTime`), which service (`eventSource`), and where the request originated (`sourceIPAddress`). These sample logs are synthetic.

`json.load()` converts JSON text into Python dictionaries and lists. The `Records` list contains the individual event dictionaries. `obj()` safely substitutes an empty dictionary for nullable nested objects so missing fields do not crash detection.

## 2. Preparation

`load_events()` reads ordinary or compressed JSON files. `analyze()` checks essential fields, parses timezone-aware timestamps, removes duplicate account/event-ID pairs, and sorts records. Sorting matters because files can arrive out of order, while login correlation depends on time.

## 3. Single-event rules

An `if` statement checks a specific combination of fields. For example, a console login must explicitly say `Success` and `MFAUsed: No` before the no-MFA rule triggers. An absent MFA field means unknown, not no MFA. Service names prevent similarly named operations from the wrong service from matching.

A request containing `errorCode` is not treated as a successful policy attachment or logging change. The root rule deliberately includes attempts, and the report preserves the outcome context.

## 4. Multiple-event correlation

A dictionary groups login failures by account, actor, and source IP. A `deque` holds recent events for each group. Old events leave the queue as the window advances. Five failures inside ten minutes create one finding, and that cluster resets. This is a simple repeated-failure detector; it does not prove brute force.

## 5. Output

Each finding includes a rule, severity, actor, source IP, event ID, evidence, and suggested review. `write_reports()` creates:

- `summary.txt` for a quick human review.
- `findings.csv` for spreadsheet filtering.
- `findings.json` for structured reuse by another program.

The report's finding count is not a count of confirmed attacks or unique compromised users.

## 6. Why tests matter

A detector must avoid alerting on clean controls as well as identify suspicious samples. The tests check both sides, plus tricky situations such as missing MFA details, failed changes, duplicates, and failures spread too far apart in time.

## Interview explanation

“I worked on an AI-assisted Python tool that analyzes synthetic AWS CloudTrail logs offline. It normalizes and deduplicates records, applies five security rules, correlates failed logins within a configurable window, and produces evidence-based reports. I validated the behavior with automated tests and documented false positives and limitations.”

Be ready to explain why missing MFA is different from explicitly disabled MFA, why denied actions should not be reported as completed changes, and how windowed correlation works. The implementation is ready to review; understanding it is the next learning step.

## Suggested personal extension

After reviewing the existing rules, add detection for a new event type with one suspicious example, one benign control, a test, and a README explanation. That creates a concrete change you can explain and defend yourself.
