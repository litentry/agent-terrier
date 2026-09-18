# Fridge — the inventory

One memory file, `viking://user/default/memories/entities/fridge/inventory.md`,
written with `mcp__openviking__write` (`mode: "replace"`) — read it with
`mcp__openviking__read` before planning.

- body: `{ "seen_at": "…", "items": [{ "name": "…", "quantity": "…", "state": "ok" | "low" | "spoiling" | "new", "last_seen": "…" }] }`
- A fridge photo REPLACES the item list for the shelves it shows and keeps
  unseen items with their old `last_seen`.
- Anything not seen for 3 photos ⇒ `low`; visibly spoiling ⇒ `spoiling` and
  a one-line alert on the next card.
- Tell the contact what changed ("新增：豆腐；牛奶快没了" / "New: tofu; milk is
  low"). Never invent items you did not see.
