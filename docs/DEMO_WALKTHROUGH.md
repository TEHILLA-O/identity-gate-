# Demonstration

Sign in to IdentityGate as `elena.vasquez` with `DEMO_USER_PASSWORD` from `.env`. She is a finance analyst with a time-boxed project contributor role.

## A. Single sign-on

Open Finance and sign in. Open Projects in the same browser. The second application should return without a password prompt. Create a report in Finance. Approve a report and change settings. Both privileged calls are denied. In Projects, update a project. Creating a project is denied.

## B. Joiner

An operator such as `owen.briggs` can post a new employee. The lifecycle row shows each stage. The directory then lists the person, and a reconciliation shows the downstream account.

## C. Mover

Move a finance employee to Engineering. The workflow diff lists finance roles removed and engineering roles added. Previous privileged extras are not kept.

## D. Leaver

`sara.okonkwo` is already departed. Her Keycloak account is disabled and the downstream account is inactive when bootstrap completed the leaver. A new leaver that cannot reach the directory stays failed.

## E. Denied API

Elena calling a leaver, or an anonymous Finance report read, is rejected by the server. The policy simulator repeats the Finance payment decision with the same reason string.

## F. Review

Priya Nair is the reviewer for the finance campaign. Approve one entitlement and revoke another. The campaign shows the decision immediately and the removal status only after Keycloak confirms it.

## G. Segregation

Marcus Hale holds report creation and payment approval. The conflict is open. An administrator can record an exception. The row stays visible as excepted.

## H. Provisioning failure

Stop the directory container and run a joiner or reconciliation. The attempt is stored as failed. Start the directory and reconcile again. Repair applies the missing accounts that the dry run listed.

## I. Assessment

As `helen.cho`, evaluate controls and export the JSON report. Expect failures for segregation, least privilege, and the unapproved batch service account. Expect `not_evaluated` only where the evidence source could not be read.

Other useful people: `amira.shah` is the identity administrator, `noah.petrov` is a project administrator without an approval record, `lina.ortiz` is an expired contractor left active until the expiry sweep, and `jonas.keller` is suspended with groups retained.
