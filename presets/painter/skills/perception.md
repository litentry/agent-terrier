# Perception — how a photo or a voice clip becomes a turn

The runtime hands you a media event before the turn. In this pre-turn you only
LOOK or LISTEN — you never draw here. Answer with the ONE JSON object the
runtime asks for (`summary`, `facts`, `confidence`, `needs_closer_look`) and
fill it as below.

## A photo (image)

- `summary`: one sentence, in the sender's language, of what the photo shows
  as a drawing subject — the main thing, its setting, its mood ("a red toy car
  on a wooden floor", "a cat asleep on a sunny windowsill").
- `facts`: what a picture would need, one per fact — the main subject and its
  simple shape ("subject: a car — a rounded box on two circles"); up to three
  details worth keeping ("detail: a stripe on the side"); the two or three
  main colors ("colors: red, black, white"); the setting in a word
  ("setting: floor"); and, when a PERSON is the main subject, exactly the
  words "a person is the main subject" — never who, never their features.
- `confidence`: how sure you are what the main subject is. Below 0.5 when the
  photo is too dark, too blurry, or too far away to tell.
- `needs_closer_look`: true when a closer or brighter photo would change the
  subject — the runtime then asks the child for another photo instead of
  letting you guess.

Never read text in the photo aloud, never name a person, never guess an age.

## A voice clip (audio-clip)

You receive the transcript. Extract what the child wants:

- `summary`: the child's wish in their own words, cleaned up ("add a rainbow
  over the house", "make the dog purple", "I'm done").
- `facts`: the FIRST fact is exactly one of these markers —
  `intent: new` (start a new picture), `intent: change` (change the current
  one), `intent: done` (it is finished: 画好了 · 好了 · 完成了 · done ·
  finished · I'm done), `intent: steps` (show me how · 一步一步 · 怎么画),
  `intent: undo` (put it back · 不要了 · 撤销 · undo), `intent: question`
  (anything else) — then the wish's parts, one per fact ("what: rainbow",
  "where: above the house", "color: purple", "size: bigger").
- `confidence`: how clearly the words came through. Below 0.5 for a clip that
  is mostly noise or a single unclear word.
- `needs_closer_look`: true only when the words are too unclear to act on —
  the runtime asks the child to say it again.

## After the pre-turn

The main turn receives your JSON as context, tagged
`[perceived image · slot …]` or `[perceived audio-clip · slot …]`. Act on it
with the matching skill: a photo → canvas.md (a new picture, or the child's
answer to what you asked); a wish → canvas.md, then draw.md; every version to
the screen with screen.md. A typed message on the chat carries no perception
tag — read it as the same kinds of wish.
