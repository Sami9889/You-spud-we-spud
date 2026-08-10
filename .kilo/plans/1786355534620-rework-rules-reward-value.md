# Plan: Rework rules to justify reward value without mentioning dollar amount

## Goal
Address the "low time-to-reward" perception by raising the quality bar and adding friction to low-effort submissions. The site should make clear that size is only one constraint, and that meaningful effort and originality are required to qualify. Do NOT mention any specific dollar value on the site.

## Files to modify
1. `index.html` — Reword rules, FAQ, and prizes sections to emphasize quality, originality, and manual review.
2. `rules.yaml` — Add stricter review rules that disqualify obvious low-effort submissions.
3. `README.md` — Align copy with the tightened rules.

## Proposed changes

### index.html
- **Rules section:** Add explicit quality criteria:
  - Must be a complete, functional project (not a prototype or stub)
  - Must demonstrate original design and interaction
  - Copy-paste tutorials and unmodified starter templates are disqualified
  - Near-duplicate or trivially similar resubmissions are not eligible
- **FAQ:** Add entries:
  - *"What counts as a real project?"* — Explain that a 2KB page built in 2 hours from a tutorial won't pass review; it needs to be something you actually designed and built.
  - *"How are submissions reviewed?"* — Explain manual review for quality and originality, not just size.
- **Prizes section:** Remove any language that makes it sound like the prize is automatic upon meeting the size limit. Add: "Every entry is reviewed by hand. Size is the starting line, not the finish line."

### rules.yaml
- Add new review rules:
  - `require_meaningful_project: true` — Reject stubs, hello-world pages, and unmodified templates
  - `require_original_design: true` — Reject trivially tutorial-based submissions
  - `manual_review_quality_gate: true` — Require reviewer to confirm originality and completeness before accepting
- Update `review` section to enforce these gates before auto-accept.

### README.md
- Update rules bullet points to match the tightened language.
- Add a note: "Every submission is manually reviewed for quality and originality before any reward is sent."

## Validation
- Review updated copy to ensure it addresses the time-to-reward concern without mentioning dollar amounts.
- No code/logic changes beyond rules config, so no test/lint impact.
