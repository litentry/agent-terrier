The local agent searches persistent knowledge through `recall_knowledge`. The canonical memory worker stores the documents; the configured local embedding model ranks them on each request. No vector database or additional memory server is required.

## Plant and read knowledge

Start the [local services](./local-services.md) and [log in an owner](./local-owner.md). These commands use that owner's protected development session and the same document client as the browser. Planting merges one stable entry key, preserves other entries and updates the category index. Repeating identical content is a no-op; changing a key's body uses the existing document history path.

Local, from the public checkout with the selected state directory:

```sh
printf '%s' 'Board the overnight train at platform seven.' |
  ./terrier memory plant travel --name developer --key railway --body-stdin
./terrier memory read travel --name developer
```

`--title` optionally supplies a display title. Body text comes from stdin, so it is not a process argument. Read output contains the requested knowledge; keep it private when the document is private. Missing, expired, mismatched or unprotected session files are refused. These commands require the guarded local development profile and loopback services; they do not create keys when an existing request key is missing.

If category indexing fails after the entry was written, the command reports that partial result and exits nonzero. Retry the same plant operation after correcting the service failure. It does not report a failed write as success or discard the stored entry.

## Share with an agent

Grant `knowledge:travel` to the agent with the existing [owner grant command](./local-owner.md). That command replaces the actor's service set: include every existing service you intend to retain, including its owner-chat publish and subscribe services. Removing this exact knowledge grant removes permission to retrieve it. Another owner's namespace with the same name is a separate store.

Ask the agent to call `recall_knowledge` with `namespace` set to `travel` and a concrete `query`. The generic action plugin discovers this tool from the daemon's shared protocol advertisement. The grant view resolves standard namespaces and the installed memory/resource namespace names only when their hashes are on chain; configuration alone grants nothing. Keep the agent's existing installed knowledge grant when adding a different shared namespace. Tool visibility refreshes periodically; exact namespace authorization is checked on every retrieval. The request cannot select a different owner or actor. The daemon acquires a fresh session, requests a namespace capability, and the worker independently checks current chain authority. An unrelated knowledge grant does not authorize this namespace.

The daemon fetches canonical entries, asks the configured model relay for embeddings, ranks them by cosine similarity and re-fetches the namespace before returning results. A refused second read or changed content aborts the result. It writes neither knowledge nor a persistent search index. Results are labeled as retrieved data, not instructions. Already delivered knowledge may remain in the agent's conversation history; revoking a grant prevents new authorized retrieval, not erasure of earlier disclosures.

## Development bounds

The shared [action contract](../../crates/agentkeys-protocol/src/sandbox_actions.rs) owns the limits: 128 entries, 1 MiB canonical source, 8 KiB per serialized stored entry, a 4 KiB query and at most three matches. The CLI also uses the document client's existing namespace/key validation. Oversized or malformed documents, duplicate keys, unavailable models, invalid vectors and dimension mismatches fail explicitly. An empty authorized namespace returns an empty result without inference.

The embedding model and dimension come from the same [local model recipe](../../presets/local-models.json) as the probe and runtime. Vectors live only for the request. This bounded, per-request approach favors a small development installation; it is not a claim of large-corpus indexing performance. Optional OpenViking integration remains a separate, unqualified integration.

## Qualification

The fast daemon tests cover semantic ranking, bounded parsing, denied first reads, revocation during embedding and changed content before disclosure. The shared plugin fixture proves the tool is registered and sent through the existing bearer-gated action route.

The explicit [managed application qualifier](./local-models.md#managed-application-qualification) plants synthetic documents through this CLI, checks owner isolation, uses the real local model to retrieve a relevant document, removes and restores the exact chain grant, and repeats retrieval in a fresh conversation after runtime recreation. It also verifies retrieval leaves canonical data unchanged. The real-chain protected data qualifier checks rejected sessions cannot modify memory or its category index. These expensive checks stay outside the ordinary source lane.

The [recorded offline application run](../../e2e/fixtures/model-qualification/macos-arm64-knowledge-2026-11-03.json) passed in 129.410 seconds on the declared macOS arm64 configuration. Complete browser and clean-install acceptance remain separate.
