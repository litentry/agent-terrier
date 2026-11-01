Agent Terrier is a local development platform with on-chain authority, protected development signing, scoped storage and Docker-managed agents. These guides are authored from the public implementation. The complete standalone release remains under development; each guide distinguishes qualified behavior from remaining acceptance work.

## Start here

1. [Prepare contracts](./contract-development.md) and the [local chain](./local-chain.md).
2. Build and start [local services](./local-services.md), or use the [lightweight terminal manager](./local-manager.md).
3. Register and log in a [development owner](./local-owner.md).
4. Prepare the [agent image](./local-agent-image.md) and [local models](./local-models.md).
5. [Create, call and archive an agent](./local-agents.md) from the CLI.

Use fresh development identities only. The development software signer is not production custody or hardware protection. Dependencies, images and models must be downloaded before offline qualification; startup never silently selects a hosted service.

## Develop and verify

- [Architecture and canonical owners](../arch.md)
- [Generated CLI reference](./cli-reference.md)
- [Contributor guide](../../CONTRIBUTING.md)
- [Local storage and authorization checks](./local-storage.md)
- [Fast and extended test lanes](./test-lanes.md)
- [Docker isolation qualification](./docker-qualification.md)
- [Development email outbox](./local-email.md)
- [Licenses and exceptions](./licensing.md)
- [Wiki source and publication](./wiki-publication.md)

The source of every page lives in `docs/wiki` in the public repository. Edit those files through a reviewed pull request. Published pages link to the exact source revision; browser enrollment, full application tool/channel workflows, website supervision, destructive reset and independent clean-install acceptance remain open in [the release epic](https://github.com/litentry/agent-terrier/issues/1).
