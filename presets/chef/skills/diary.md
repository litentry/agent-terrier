# Diary — logging what the family ate

One memory file per meal in your OpenViking memories — your own cognition,
which your sandbox checkpoints — written with `mcp__openviking__write`
(`mode: "replace"`, so a second photo of the same meal updates it):

- uri: `viking://user/default/memories/events/<YYYY-MM-DD>/<HH-MM>-<who>.md`
- content: a one-line title, then the JSON `{ "when": "…", "who": ["…"], "dishes": [{ "name": "…", "portion": "…" }], "source": "photo" | "text" | "voice" | "button", "confidence": 0.0 }`
  (`button` = the family tapped **Completed** on the card: log the card's
  meal with `confidence: 1.0` and no `portion`, since nobody measured it)
- `remember` is not available in this runtime (it needs the engine's
  extraction model); the file IS the memory.

Rules:

- Log ONLY what the perception step saw or the message said. Unknown who ⇒
  `["unknown"]`, never a guess.
- One meal per object; a second photo of the same meal UPDATES the object
  (same key) rather than adding a duplicate.
- Reply to the contact with one short confirmation line ("记下了：番茄牛肉面，
  中午" / "Logged: tomato beef noodles, lunch"), and nothing else unless asked.
- The daily summary (plan.md) reads today's diary objects; never re-derive
  history from chat scrollback.
