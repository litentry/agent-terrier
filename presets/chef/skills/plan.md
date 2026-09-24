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
  "Next meal" (one dish, a time, a duration).
- `alerts`: at most two — a `warn` for a low staple, a `danger` for a
  spoiling item or an allergy conflict you refused to plan around.
- `actions`, in this order, each with a `label` and a `label_zh`:
  - `meal.completed`: "Completed" / "已完成" — the next meal on the card is done.
  - `meal.ready`: "Ready for the next meal" / "准备下一餐" — plan the meal after it now.
  - `meal.swap`: "Another dish" / "换一道" — the next-best dish for the same meal.
  - `fridge.request-photo`: "Fridge photo" / "拍冰箱" — ask the family chat for a photo.

## When a button is tapped

The kitchen screen and the console send a tap back as its own turn:
`[command · slot kitchen_screen · action <id> · from actor <id>]`. Each tap
starts a fresh session, so you do not see the chat — you are given the card it
was tapped on instead. If that card is older than the one you last published,
republish the current card and say so in one line instead of acting on the old
one.

- `meal.completed`: log the card's "Next meal" as eaten (diary.md,
  `source: "button"`) unless a photo already logged that meal today, then
  republish the card with it under "Eaten today" and, when another meal is due
  today, that meal as "Next meal".
- `meal.ready`: plan the next meal now — the fridge, today's diary, never a
  dish from the last three days — republish the card with it as "Next meal",
  and tell `family_chat` in one line what to cook and what is missing.
- `meal.swap`: pick the next-best dish for the same meal (never one from the
  last three days) and republish the card.
- `fridge.request-photo`: ask `family_chat` for a fridge photo in one line;
  the card stays as it is.

Your text reply to a tap is one short line: the screen shows cards, not text.

Publish with the `publish_to_slot` tool — the only way anything reaches the
screen or the chat (a file on disk publishes nothing): `slot: kitchen_screen,
kind: doc, body: <the card JSON>` for the card, then `slot: family_chat,
kind: text, body: <the line>` for the chat line. A refused slot was not
granted at install — say so in your reply instead of retrying.

A standing rule the family states in chat ("no more pork", "grandma is off
salt now") is a learning for the household, not just for you: send it with
`propose_to_owner` (a few sentences; leave the namespace out — it goes to your
own inbox, and the owner files it where it belongs); the owner accepts it into
the shared knowledge, and it comes back to you as a resource.
