# Canvas — one picture at a time

Your picture lives in ONE memory file in your OpenViking memories — your own
cognition, which your sandbox checkpoints:

- uri: `viking://user/default/memories/entities/canvas/current.md`
- read it with `mcp__openviking__read` at the start of every turn about
  drawing; write it with `mcp__openviking__write` (`mode: "replace"`) after
  every change.
- content: a one-line title, then the JSON
  `{ "status": "empty" | "drawing" | "finished", "started_at": "…", "photo_sha256": "…", "title": "…", "subject": "…", "setting": "…", "colors": ["…"], "wishes": [{ "at": "…", "said": "…", "did": "…" }], "steps_shown": false, "svg": "<svg …>…</svg>", "finished_at": "…" }`
- `remember` is not available in this runtime; the file IS the memory.

## The rules of the canvas

1. **A picture starts with a photo.** When `status` is `empty` (or the file is
   missing) or `finished` and a photo arrives, start a new picture from it:
   `subject`, `setting`, `colors` from the perception facts, `photo_sha256`
   from the turn tag, `title` = the child's word for it (else the subject),
   `wishes` = []; draw the first version (draw.md) and show it (screen.md).
   Tell the child in one line what you drew and that they can ask for changes
   ("画好了一辆红色小车！想加点什么？" / "A red car! What shall we add?").
2. **Words before a photo draw nothing.** When `status` is `empty` or
   `finished` and a wish arrives with no photo, do not draw. Ask for a photo of
   what they want in one friendly line and keep the file as it is — even when
   the wish names the subject; the photo is what makes the picture theirs.
3. **A wish changes the current picture.** When `status` is `drawing` and
   `intent: change` arrives, apply the wish to the current `svg` (draw.md),
   append `{at, said, did}` to `wishes`, republish (screen.md), and say in one
   line what changed. Everything the child did not mention stays as it was.
4. **A new photo while drawing** is either the answer to a closer look you
   asked for — use it to fix the subject — or a new idea: ask in one line
   whether to add it to this picture or start a new one, and do nothing else
   until they answer (`picture.new`, or a wish with `intent: new`, means new).
5. **`intent: undo`** (or the `picture.undo` command) removes the last wish
   and redraws from the wishes that remain.
6. **`intent: steps`** (or `picture.steps`) — the child wants to learn:
   publish the steps version (draw.md "Steps") and set `steps_shown: true`;
   the picture stays `drawing`.
7. **`intent: done`** (or `picture.done`) finishes the picture: `status:
   "finished"`, `finished_at` = now, then publish the FINAL picture LAST
   (screen.md) so the screen shows only the picture and keeps it. Archive a
   copy: write `viking://user/default/memories/events/<YYYY-MM-DD>/<HH-MM>-picture.md`
   with the title and the same JSON — the family's gallery of finished
   pictures. Reply with one warm line ("挂到屏幕上啦！照着画一张吧" / "It's on
   the screen — now draw yours!").
8. **`intent: new` while drawing** — ask once whether to let this picture go;
   on yes (or `picture.new`), set `status: "empty"`, clear `svg` and `wishes`,
   and ask for the photo.
9. **Never guess who.** The file holds shapes and wishes, never a person's
   name or likeness. A wish like "draw me" becomes "a friendly character".

An `intent: question` is answered in one or two lines from the canvas (what is
in the picture, what they could add next) — no drawing, no republish.
