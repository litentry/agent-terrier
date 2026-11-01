The local channel CLI publishes text and reads messages using an existing development owner session. It calls the same typed channel client as the website and obtains capabilities through the native service client. The broker, worker and object service retain their independent authority checks.

## Publish and read

Prepare [local services](./local-services.md), register a [development owner](./local-owner.md), and log in. Use the same private state directory for these commands.

Local, from the prepared public checkout:

```sh
printf %s 'Hello from the local CLI' | ./terrier channel publish example \
  --name developer --text-stdin
./terrier channel poll example --name developer
```

Publish accepts 1–65,536 UTF-8 bytes on stdin and returns an event identifier. It creates an incoming text event. Poll returns the shared worker response under `response`: `events` contains messages and `cursor` identifies the last read position. Inline message bodies are base64 encoded in `body`; the command does not silently decode or discard event metadata.

Local, in the same checkout and shell, to wait for messages after a previous poll:

```sh
channel_cursor="$(./terrier channel poll example --name developer | jq -r .response.cursor)"
./terrier channel poll example --name developer --after "${channel_cursor}" --wait-seconds 10
```

The wait is bounded to 25 seconds. Channel identifiers use the shared resource-name validation. A channel belongs to its owner: another owner's channel with the same name is a separate feed. Polling does not delete messages. Publishing and polling do not grant an agent access; use the owner's explicit grant operation for an agent's `channel-pub:<id>` or `channel-sub:<id>` scope.

## Session and transport

The CLI reads the existing protected owner session and request key. It rejects expired or mismatched sessions, missing keys, unsafe session files and nonlocal service addresses. It passes no session bearer or key value through command arguments, follows no redirects and ignores inherited HTTP proxies. Failed service responses report status without echoing response bodies or endpoint details.

This is a development software-signing flow, not production custody. The CLI prints requested message contents in its JSON output; protect captured output accordingly. Ordinary service restart retains the encrypted channel database and its original key. See [local storage](./local-storage.md) for storage and revocation behavior.

## Qualification and scope

Local, from the public checkout after preparing the service binaries and cached contract inputs:

```sh
python3 scripts/tests/qualify_local_credential_cli.py
```

One shared fixture qualifies both credential and channel commands against real local contracts, broker login and workers. Channel checks cover exact text round trip, cursors, owner separation, encrypted persistence, restart, input bounds, rejected sessions with unchanged storage, remote-address refusal, redirect refusal and proxy-independent access. Existing worker qualification separately checks live scope and device revocation.

This command currently supports owner text publish/poll. Attachments, streaming media and complete agent tool/channel conversation acceptance remain separate work in [the release epic](https://github.com/litentry/agent-terrier/issues/1).
