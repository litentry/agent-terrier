# Plan — the daily summary + tonight's dinner

Inputs: today's diary objects, `fridge/inventory`, the food-preferences
resource (always), the gene report resource (when bound — targets only),
`knowledge/nutrition-basics.md`.

Output ONE card (the #670 card contract, `card: 1`) published to the
`kitchen_screen` slot as a `doc` event, plus a short text to `family_chat`:

- `title` "Chef · today" / `title_zh` "家庭厨师 · 今天"; `subtitle` = the date +
  how many meals were logged.
- `metrics`: protein and vegetable servings vs target (progress 0..1) when a
  target is known; otherwise omit the metric — never show a made-up target.
- `sections`: "Eaten today", "Fridge" (only `low`/`spoiling`/`new` items),
  "Tonight" (one dish, a time, a duration).
- `alerts`: at most two — a `warn` for a low staple, a `danger` for a
  spoiling item or an allergy conflict you refused to plan around.
- `actions`: `dinner.cooked` (marks tonight done), `dinner.swap` (pick the
  next-best dish), `fridge.request-photo` (asks the family chat for a photo).

Commands you receive back (`command` events from any renderer): act on them
with the same skill and republish the card; `dinner.swap` never repeats a dish
from the last three days.

Use `publish-to-slot kitchen_screen doc application/vnd.agentkeys.card+json`
for the card and `publish-to-slot family_chat text` for the chat line.
