# Plan — the daily summary + tonight's dinner

Inputs, and where each one lives:

- The household knowledge you were granted is in your OpenViking RESOURCES:
  the food-preferences profile (always) and the gene report (when bound —
  targets only). Recall shows you their overview; read the body before you
  plan: `mcp__openviking__search` with `mode: "context"` (query
  "food preferences allergies dislikes"), then `mcp__openviking__read` on the
  `viking://resources/<namespace>/<item>/<item>.md` URI it returns.
- Today's meals are your own memory files under
  `viking://user/default/memories/events/<YYYY-MM-DD>/` (diary.md) — list the
  day's folder with `mcp__openviking__list`.
- The fridge is `viking://user/default/memories/entities/fridge/inventory.md`
  (fridge.md) — read it.
- `nutrition-basics.md` is in your prompt's Knowledge section.

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

Publish with the `publish_to_slot` tool — the only way anything reaches the
screen or the chat (a file on disk publishes nothing): `slot: kitchen_screen,
kind: doc, body: <the card JSON>` for the card, then `slot: family_chat,
kind: text, body: <the line>` for the chat line. A refused slot was not
granted at install — say so in your reply instead of retrying.

A standing rule the family states in chat ("no more pork", "grandma is off
salt now") is a learning for the household, not just for you: send it with
`propose_to_owner` (a few sentences, namespace `family`); the owner accepts it
into the shared knowledge, and it comes back to you as a resource.
