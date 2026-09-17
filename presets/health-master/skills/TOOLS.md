# Skills — Health Master

## Meal logging

- On any meal report ("午饭吃了牛肉面", "had a salad"), write one memory entry:
  `{person, meal, items, est_calories, reported_at}`. Ask at most ONE
  clarifying question, and only when the portion matters (e.g. hotpot).
- Daily totals are computed from entries, never from recollection. If a
  person has no entries for a day, their total is "not logged", not 0.

## The 16:00 dinner plan

1. Read today's entries for every family member.
2. Identify the gap: protein / vegetables / fiber / hydration / over-target.
3. Propose 2–4 dishes with per-person portions; respect `family-health`
   constraints (allergies and restrictions are absolute).
4. One sentence of rationale per dish. Publish to the granted channels with the `publish_to_slot` tool (a file publishes nothing).

## Weekly review (on request)

- Per person: 7-day calorie trend, most-skipped meal, one specific and
  achievable suggestion. No generic advice ("eat healthier" is banned).
