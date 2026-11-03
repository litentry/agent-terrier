Agent Terrier is a local development platform with on-chain authority, protected development signing, scoped storage and Docker-managed agents. These guides are authored from the public implementation. Start with the quickstart and consult the qualification record for the tested development configuration and remaining release gate.

## Start here

Follow the [complete local quickstart](./quickstart.md) for preparation, startup, owner registration, a CLI model reply and browser access. The focused guides below explain each component.

1. [Prepare contracts](./contract-development.md) and the [local chain](./local-chain.md).
2. Build and start [local services](./local-services.md), or use the [lightweight terminal manager](./local-manager.md).
3. Register and log in a [development owner](./local-owner.md).
4. Prepare the [agent image](./local-agent-image.md) and [local models](./local-models.md).
5. [Create, call and archive an agent](./local-agents.md) from the CLI.

Use fresh development identities only. The development software signer is not production custody or hardware protection. Dependencies, images and models must be downloaded before offline qualification; startup never silently selects a hosted service.

## Develop and verify

- [Qualification and limits](./qualification.md): exact source/image identities, measured results and unsupported capabilities.

- [Architecture and canonical owners](../arch.md)
- [Adapter contracts and compatibility](./adapter-contracts.md)
- [Generated CLI reference](./cli-reference.md)
- [Contributor guide](../../CONTRIBUTING.md)
- [Local storage and authorization checks](./local-storage.md)
- [Publish and read channel messages](./local-channels.md)
- [Plant and retrieve persistent knowledge](./local-knowledge.md)
- [Fast and extended test lanes](./test-lanes.md)
- [Docker isolation qualification](./docker-qualification.md)
- [Local website configuration](./local-website.md)
- [CLI approval of a local browser](./local-browser.md)
- [Development email outbox](./local-email.md)
- [Licenses and exceptions](./licensing.md)
- [Wiki source and publication](./wiki-publication.md)

The source of every page lives in `docs/wiki` in the public repository. Edit those files through a reviewed pull request. Published pages link to the exact source revision; the [qualification record](./qualification.md) separates completed localhost acceptance from unsupported capabilities and the remaining release gate.
