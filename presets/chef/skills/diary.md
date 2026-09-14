# Diary — logging what the family ate

Keyed memory objects under your own namespace (`knowledge:app-chef`), one per meal:

- key: `diary/<YYYY-MM-DD>/<HH-MM>-<who>`
- body: `{ "when": "…", "who": ["…"], "dishes": [{ "name": "…", "portion": "…" }], "source": "photo" | "text" | "voice", "confidence": 0.0 }`

Rules:

- Log ONLY what the perception step saw or the message said. Unknown who ⇒
  `["unknown"]`, never a guess.
- One meal per object; a second photo of the same meal UPDATES the object
  (same key) rather than adding a duplicate.
- Reply to the contact with one short confirmation line ("记下了：番茄牛肉面，
  中午" / "Logged: tomato beef noodles, lunch"), and nothing else unless asked.
- The daily summary (plan.md) reads today's diary objects; never re-derive
  history from chat scrollback.
