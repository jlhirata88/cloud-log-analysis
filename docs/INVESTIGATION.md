# Synthetic investigation and validation

## Scenario

A fictional analyst identity performs routine reads, signs in without MFA, stops a trail, receives AdministratorAccess, and has five failed console logins. A root identity also lists buckets. This is a demonstration sequence, not a claim that these events establish a causal attack chain.

## Findings from the default dataset

| Evidence | Finding | Suggested investigation |
| --- | --- | --- |
| synthetic-004: explicit successful sign-in, MFAUsed No | NO_MFA_LOGIN | Verify sign-in context and MFA policy. |
| synthetic-005: Root identity | ROOT_ACTIVITY | Verify who used root and whether the action was authorized. |
| synthetic-006: StopLogging without errorCode | LOGGING_CHANGE | Verify change approval and the trail's current logging state. |
| synthetic-007: AttachUserPolicy with AWS AdministratorAccess | ADMIN_POLICY | Review the grant, target identity and least privilege. |
| synthetic-008 through synthetic-012: five failed logins in four minutes | LOGIN_BURST | Investigate the actor/IP and subsequent login activity. |

The failed StopLogging attempt, ReadOnlyAccess attachment, and successful login with unknown MFA status are negative controls and should not generate findings under these rules.

## Verified execution

Validation performed in the build workspace with Python's standard-library unittest runner. All 13 automated tests passed. The mixed dataset produced 15 analyzed events and 5 findings (4 High, 1 Medium). The separate normal baseline produced 3 analyzed events and 0 findings. Reports in the repository were generated from the mixed dataset using default settings.

## Assessment

These signals justify investigation, not a confirmed compromise finding. There is no real account, malicious source, production deployment, containment action or remediation outcome in this simulation. In a real investigation, confirm resource state and change approvals, preserve evidence, review related activity, and coordinate authorized remediation.
