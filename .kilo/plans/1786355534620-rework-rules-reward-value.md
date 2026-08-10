# Plan: Make the challenge harder to justify reward value

## Goal
Address the "low time-to-reward" perception by making the challenge itself genuinely harder, so the reward feels commensurate with the effort. The core complaint: a 2KB project can be built in ~2 hours, making a ~$30 parcel feel disproportionate. Making the tiers harder raises the skill/effort bar.

## Key Design Decisions

### 1. Lower size limits across all tiers
| Current | Proposed |
|---|---|
| Standard: < 15KB | Standard: < 10KB |
| Hard Mode: < 5KB | Hard Mode: < 3KB |
| Ultra Hard: < 2KB | Ultra Hard: < 1KB |

### 2. Add a "Judges' Pick" selection layer
Not every passing submission gets the full parcel. After passing automated checks, submissions are ranked by:
- Originality (not tutorial-based)
- Completeness (not a stub)
- Technical execution within constraints

Only the top ~50% of reviewed submissions receive the full parcel for that tier. Others receive a digital shoutout/recognition but no physical parcel. This creates scarcity and makes the reward feel earned.

### 3. Tighten review automation to catch low-effort submissions
- `auto_accept_ultra: false` (already in current plan)
- Add heuristics that flag submissions likely built from tutorials (common patterns, generic variable names, etc.)
- Require minimum interactivity/complexity signals (event listeners, state changes, etc.)

## Files to modify
1. `rules.yaml` — Update tier limits, add judges-pick logic config
2. `index.html` — Update all tier references, add explanation of selection process
3. `README.md` — Align tier limits and selection process description

## Open Questions
- Should the "top ~50%" threshold be configurable or fixed in code?
- Should there be a minimum number of submissions before judges-pick kicks in (e.g., only if >10 submissions in a batch)?
- What's the exact heuristic for flagging tutorial-based code? Pattern matching on common tutorial variable names (`x`, `y`, `temp`, generic game loop structures)?
