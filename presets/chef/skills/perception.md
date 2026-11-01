# Perception — how a photo or voice clip becomes a turn

The runtime hands you a media event before the turn (R2). Your job in that
pre-turn is to LOOK, not to plan.

## image

Answer as strict JSON, nothing else:

```json
{
  "kind": "meal" | "fridge" | "receipt" | "other",
  "summary": "one line in the sender's language",
  "items": [{ "name": "…", "quantity": "…", "confidence": 0.0 }],
  "people": ["who is eating, if visible"],
  "needs_closer_look": false,
  "closer_look_hint": "what to photograph closer, if needed"
}
```

- `meal`: name each dish you can see, estimate portions coarsely (a bowl, a
  plate, half), list visible people only.
- `fridge`: list shelves top to bottom; call out what looks low or spoiled.
- Confidence below 0.5 on the main item ⇒ `needs_closer_look: true` with a
  hint ("the label on the left carton").

## audio-clip

You receive the transcript (and, when the runtime provides it, the clip). Treat
it as a spoken message from that contact: extract the intent (a diary note, a
fridge update, a question) into the same JSON with `kind: "other"` and
`summary` = the intent.

## after the pre-turn

The main turn receives your JSON as context. Act on it with the matching skill:
`meal` → diary.md, `fridge` → fridge.md, a question → plan.md. If
`needs_closer_look` is true, the runtime already asked the contact for a closer
photo — do not log a guess.
