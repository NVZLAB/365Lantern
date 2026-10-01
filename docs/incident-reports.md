# Incident reports

After a live or offline investigation, open **Report**. Enter the case reference,
analyst name, investigation summary, affected accounts and potential impact and next steps. Write these fields for the client contact; keep
technical evidence references in individual assessment notes and identify uncertainties.

Select an automated indicator to inspect its original supporting observations.
Classify it as Unexplained, Expected activity, Suspicious or Confirmed malicious.
An analyst name and supporting notes are required for every saved assessment.
Classification never modifies the detector output or original evidence. A confirmed
malicious classification is the analyst's judgment, not an automated or independently
verified verdict. Unassessed indicators remain unexplained.

Use **Save assessment to session** before moving on. Pending indicator edits trigger
a save/discard/cancel prompt on navigation, export and session-changing actions.
Report narrative fields update in memory as you type. No autosave or network reporting
is performed. Export before starting a new investigation, clearing the session or
exiting. These actions discard the in-memory case, including saved assessments.

Related searches preserve existing report text and assessments for unchanged evidence.
Reviews are keyed to the tenant, detector version/output and supporting evidence contents;
changed observations do not silently inherit an old review. Unmatched earlier reviews
are retained in the export and labeled as not applied. Reassessing an indicator replaces
its previous review; this is not an immutable audit log. Revisit the overall summary and
impact after adding related evidence.

## Exports

- **Export report HTML** writes a standalone readable report. Open it locally in a
  browser and use Print / Save as PDF. It contains no scripts or external resources;
  all supplied text is HTML-encoded. PDF generation is performed by the browser.
- **Export report + evidence ZIP** and Findings' **Export Findings** write the same
  thirteen-file archive: report.html, report.json, evidence.json, summary.txt,
  findings.json/csv, suspicious.json/csv, timeline.json/csv, response.json/csv and manifest.json.
  The manifest hashes every other archive entry, including both reports.

The HTML is a client-facing executive summary: what happened, the investigation
period, who was affected, potential business impact, review status, uncertainties
and investigator recommendations or reported actions. It summarizes up to five
analyst-classified concern categories and eight distinct incomplete source/status
pairs, with a pointer to the full package for additional details. Counts describe
observations, not incidents or people. Missing narratives are labeled as not established.

Internal assessment notes, event-by-event timelines, raw records, exact evidence IDs,
import hashes and technical failure details are omitted from HTML. They remain in
report.json, evidence.json and the existing timeline/suspicious JSON/CSV exports.
The HTML does not infer an incident's start/end from the search window or invent
containment actions. Review the client-facing narrative before sharing.

All exports contain sensitive case material, including analyst names and notes.
They are not encrypted or redacted. Choose an appropriate destination and handle them
under your incident procedures. Hashes detect changes; they do not independently prove
provenance, analyst identity or legal chain of custody. Preserve the original archive.
This milestone does not support reopening report drafts or final approval/signatures.
The technical timeline exports retain their full contents; the HTML deliberately summarizes them.

The HTML automatically summarizes actions recorded by the Response workflow, including
accepted, denied, unperformed and uncertain outcomes. Detailed records stay in response.json/csv.
Narrative recommendations remain analyst-reported; adding an action prompt never executes it.
See [controlled response](controlled-response.md) for the test workflow and verification limits.

## Security hardening plan
Choose a suggested action and add it to the next-steps field. Suggestions cover
monitoring, phishing training, geographic access policies, phishing-resistant MFA,
least privilege, application governance, mail protection and incident readiness. Immediate response operations are recorded separately. Every action
starts as Proposed — not performed, with editable scope, owner, target date and
completion evidence. These are prompts, not tenant operations or automatic recommendations
that every organization must implement. Review placeholders before sharing the report.

Application grant entries now resolve service-principal display names, application IDs
and publisher labels using existing authorized directory read access. Client/resource
object IDs and original grant records remain in evidence. A directory name is not a
trust verdict. Missing permissions, deleted objects, cancellation and lookup limits
leave unresolved IDs and an explicit coverage gap; collection of grants continues.

References: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get
and https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account
