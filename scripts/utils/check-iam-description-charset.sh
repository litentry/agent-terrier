#!/usr/bin/env bash
# IAM CreateRole / CreatePolicy --description accepts ONLY printable ASCII +
# Latin-1 (the regex IAM quotes back: tab/LF/CR plus x20-x7E plus xA1-xFF).
# A fancier Unicode char fails the AWS call at RUN time with an opaque
# ValidationError naming only that regex. It bit provision-ci-deploy-role
# (#101, fixed by hand plus a comment) and then provision-speech-role AGAIN
# (live 2026-07-16: the #480 dual ceremony died at step 19 on a U+2192 arrow
# in the speech-role description). Twice = a gate, not a comment.
#
# Byte-level approximation on purpose (portable to macOS, whose BSD grep has
# no -P): every UTF-8 encoding of the punctuation people actually paste
# (arrows, em dashes, smart quotes, CJK) carries a byte in 0x80-0xA0, which
# the allowed-set complement catches. A codepoint whose every UTF-8 byte lands
# in 0xA1-0xFF could slip through; the repo's writing style does not produce
# those. Genuine Latin-1 (like the section sign in arch.md citations) passes,
# as IAM allows it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

bad="$(grep -rn -- '--description' scripts/ 2>/dev/null \
  | grep -v 'check-iam-description-charset.sh' \
  | perl -ne 'print if /[^\x09\x0A\x0D\x20-\x7E\xA1-\xFF]/' || true)"

if [ -n "$bad" ]; then
  echo "fail  non-Latin-1 characters inside aws --description lines; IAM rejects these" >&2
  echo "      at runtime (ValidationError on the description charset):" >&2
  printf '%s\n' "$bad" >&2
  echo "      Replace the char with ASCII (\"->\", \"-\", plain quotes)." >&2
  exit 1
fi
echo "ok    aws --description strings are IAM-charset-safe"
