# Plan: Make challenge harder + add Judges' Pick selection

## Goal
Raise the effort bar and add scarcity so the reward feels commensurate with the work. Two changes: lower size limits across all tiers, and only top ~50% of reviewed submissions get the full physical parcel (others get digital recognition only).

## Changes

### 1. Lower tier size limits

| Tier | Current | New |
|---|---|---|
| Standard | < 15KB | < 10KB |
| Hard Mode | < 5KB | < 3KB |
| Ultra Hard | < 2KB | < 1KB |

Update in:
- `rules.yaml` — `tiers` block
- `index.html` — prizes section, rules table headers, any FAQ references

### 2. Add Judges' Pick selection

After passing automated checks, submissions are ranked by:

- **Originality** — not tutorial-based, not a clone
- **Completeness** — not a stub, has real interactivity/state
- **Technical execution** — how well it works within constraints

Top ~50% per tier per review batch receive the full physical parcel. The rest receive a digital shoutout in `#ship` and are listed on the site, but no parcel is sent.

No minimum batch size — the 50% threshold applies even if only 1 submission that week.

### 3. Update review config

In `rules.yaml`:

```yaml
review:
  size_field: file_size_kb
  size_must_match_tier: true
  auto_accept_ultra: false
  require_manual_review: true
  require_meaningful_project: true
  require_original_design: true
  manual_review_quality_gate: true
  judges_pick_enabled: true
  judges_pick_ratio: 0.5
```

### 4. Update website copy

**`index.html` — Prizes section intro (around line 789):**
Replace:
> "Three tiers, each one stacks on the last."

With:
> "Three tiers, each one stacks on the last. Not everyone who qualifies gets a parcel — submissions are reviewed by hand and ranked by originality, completeness, and execution. Top half per tier receives the full package; the rest get a public shoutout."

**`index.html` — Rules table (after "Must demonstrate original design and interaction"):**
Add row:
> "Judges' Pick: not every passing submission gets a parcel — ranked by originality, completeness, and execution; top ~50% per tier receive the full package" → Required / Required / Required

**`index.html` — FAQ (update "Is the parcel really more than potatoes?"):**
Add sentence:
> "On top of that, only the top-ranked submissions per tier receive the full physical parcel — the rest get a public shoutout and recognition on the site."

### 5. Backend changes needed (out of scope for this plan)

In `functions/api/review.js`:
- After current review checks pass, compute a `judges_score` (0–1) based on originality, completeness, execution heuristics
- Return `judges_pick: true/false` in the review response
- Add endpoint to list/rank submissions for admin review

### 6. Files to modify
- `rules.yaml` — tier limits, review config
- `index.html` — tier limit numbers, prizes intro, rules table, FAQ
- `README.md` — tier table, rules bullets

### 7. Not in scope
- Backend implementation of ranking/scoring logic
- Actual shipment logistics
- Any dollar amount mentioned on the site

## Validation
- Verify all tier limit numbers are consistent across files
- Verify rules table and FAQ reflect new constraints
- Verify review.yaml config syntax is valid
