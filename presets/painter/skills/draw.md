# Draw — the picture is a small SVG a child can copy

You author the picture yourself, as SVG text, and publish it with
`publish_to_slot` (screen.md). No tool makes pictures for you; your shapes do.

## The contract (every picture, every version)

- One root `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800">` —
  landscape; the screen scales it to fit. No `width` / `height` attributes.
- Only shapes: `rect`, `circle`, `ellipse`, `line`, `polyline`, `polygon`,
  `path`, `text`, `g`. Never `script`, `foreignObject`, `image`, `use`,
  `style`, `href`, `url(...)`, or anything that points outside the file. Style
  with attributes, not classes.
- Small: under 60 KB and under 80 shapes. The `body` of `publish_to_slot` is
  the SVG text verbatim, `kind: image`, `content_type: image/svg+xml`.
- Background: a light, flat color (cream `#fff7e6`, or a pale sky `#e8f4ff`)
  as the first `rect`, so a copy on white paper looks the same.
- Outlines: every shape has a dark stroke `#1f1a17`, `stroke-width` 8–14 at
  this size, `stroke-linejoin="round"` and `stroke-linecap="round"`. Flat
  fills only — no gradients, shadows or textures. Four to six colors from one
  cheerful palette: red `#e94f37`, yellow `#f6b93b`, green `#3ba55d`, blue
  `#3a86ff`, purple `#a663cc`, pink `#ff8fab`, brown `#8d5524`, white.
- Shapes a child can name: circles, ovals, rounded boxes, triangles, simple
  curves. A cat is a circle head, triangle ears, an oval body, a curly tail; a
  house is a box, a triangle roof, a door, two windows. Build every subject
  from 3–8 such parts; add a ground line and one or two setting details (a
  sun, a cloud, grass tufts) — never a busy scene.
- One subject rules the picture and fills about half the height; the rest
  breathes.
- Text: at most ONE short title (the child's word for it, at most 12
  characters, `font-family="sans-serif"`, `font-size="44"`, bottom-left).
  Nothing else is ever written.
- People become characters: a round head, dot eyes, a big smile, stick arms —
  the same friendly character every time, looking like nobody.

## Changing a picture

Apply the child's wish to the CURRENT svg: add, move, recolor, resize or
remove the part they named, and leave every other element exactly where it
was (a child who is copying it needs the picture to stay still). "Bigger" is
about 1.4×, "smaller" about 0.7×, "more" means one or two more, not ten. A
color word picks the nearest palette color. If a wish would break the contract
(a frightening thing, a written message, a real face), do the gentle version
and say so in your one line.

## Steps (when the child asks how)

Publish a second SVG, the same size, that shows how to draw the picture in 3–5
numbered steps, left to right, top to bottom: step 1 is the biggest shape
alone; each next step adds the next part in the dark stroke while the earlier
parts stay light grey `#c9c2b8`; the last step is the finished picture. Each
step sits in its own box with a big number (`font-size="60"`). The child comes
back to the picture with the card's **Back to the picture** button or by
asking — republish the current picture then.

## Before publishing — check

The SVG parses (every tag closed), starts with `<svg`, carries the `viewBox`,
has no `script`, `image`, `foreignObject`, `use`, `style` or `href`, and is
under 60 KB. A picture that fails a check is fixed, never sent.
