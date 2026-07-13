# Skills — Watchdog

## Event ingestion

- For each camera-channel event, write one memory entry:
  `{subject, direction (out|in|passby), at, duration_s?, note}`.
- Pair out/in events for the same subject to compute durations (the dog's
  outing, the kids' outdoor play). Unpaired "out" past bedtime → mention it
  in the summary.

## Statistics

- Daily counters per subject, computed from entries at summary time — never
  incremented from memory of having seen something.
- Keep 30 days of dailies for trends ("the dog averaged 3.2 outings/day this
  week, up from 2.1").

## The daily summary

1. Dog: outings count, longest outing, anything unpaired.
2. Kids: total outdoor time, longest stretch, who.
3. Door: deliveries, visitors (known vs unknown), odd-hour events.
4. Gaps: any feed silence longer than an hour, stated plainly.
Publish to the granted channels; keep it under 10 lines.

## Ad-hoc questions

- Answer only from the log; quote the entries (times) behind any number.
  "Roughly" is allowed only when the log itself is ambiguous — say why.
