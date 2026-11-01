# Screen — what the kids' screen shows and how taps come back

The kids' screen draws the NEWEST thing on its feed: when your last event is a
`doc` card, it shows the card beside the picture (the buttons live on the
card); when your last event is an `image`, it shows the picture alone, full
screen, and keeps it there until the next event. Every version of the picture
is an `image` event; the card is a small `doc` (the `card: 1` contract) you
publish after a draft so the child has buttons.

Publish ONLY with the `publish_to_slot` tool — a file on disk publishes
nothing:

- the picture: `slot: kids_screen, kind: image, content_type: image/svg+xml, body: <the SVG text>`
- the card: `slot: kids_screen, kind: doc, body: <the card JSON>`
- your line back to the family when the turn came from a button:
  `slot: kids_chat, kind: text, body: <the line>` (a turn that came from the
  chat or the mic is answered by your reply text itself)

A refused slot was not granted at install — say so in your reply instead of
retrying.

## While drawing — picture, then card

1. `image` → the picture (draw.md).
2. `doc` → the card, so the buttons are on screen:
   - `title` "Painter · drawing" / `title_zh` "小画家 · 画画中"; `subtitle` =
     the picture's title and how many wishes so far ("a red car · 3 wishes" /
     "红色小车 · 3 个愿望").
   - `sections`: ONE section "You asked for" / "你说过" with the last three
     wishes as items (`text` = the wish; `text_zh` when the child spoke
     Chinese; `tag: "done"`).
   - `actions`, in this order, each with a `label` and a `label_zh`, and
     `command` equal to the id:
     - `picture.done`: "Finished! ✓" / "画好了 ✓" — keep it on the screen.
     - `picture.steps`: "Show me how" / "一步一步教我" — the steps version.
     - `picture.undo`: "Put it back" / "撤销一步" — remove the last change.
     - `picture.new`: "New picture" / "画新的" — start over (asks for a photo).
   - No `metrics`, no `alerts` (a child's screen shows no warnings);
     `updated_at` = now, in unix seconds.
3. Steps: `image` (the steps SVG), then the same card with `picture.back`
   ("Back to the picture" / "回到画") as its second action in place of
   `picture.steps`.

## Finished — the picture LAST

When the child is done, publish the final `image` and nothing after it: the
screen shows only the picture, full screen, and keeps it lit until the next
picture starts. Never publish a card after a finished picture.

## When a button is tapped

A tap arrives as its own turn: `[command · slot kids_screen · action <id> ·
from actor <id>]` followed by the command name. Each tap starts a fresh
session with the card it was tapped on — read the canvas file first
(canvas.md); if that card is older than the one you last published, republish
the current state and say so in one line instead of acting on the old one.

- `picture.done` → canvas rule 7 (finish; final picture last; archive).
- `picture.steps` → canvas rule 6 (steps image, then the card with `picture.back`).
- `picture.back` → republish the current picture, then the drawing card.
- `picture.undo` → canvas rule 5 (drop the last wish, redraw; picture, then card).
- `picture.new` → canvas rule 8 (empty the canvas; ask the chat for a photo in one line).

Your text reply to a tap is one short line: the screen shows pictures, not
text.
