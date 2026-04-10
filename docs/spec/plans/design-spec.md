# AgentKeys — Original v0 Product Vision (2026-04-07)

> **Historical stub.** This is the original v0 product vision from 2026-04-07. The v0 implementation plan is in [`ceo-plan.md`](ceo-plan.md). Preserved for historical reference.

## Summary

AgentKeys solves the auth layer problem when setting up new AI agent machines. Instead of manually creating accounts and API keys across dozens of services, AgentKeys automates the entire flow with crypto-native billing.

## Pain Points

| Service | Current Pain |
|---------|-------------|
| Google Account | KYC by mobile number or business account |
| LLM APIs (OpenRouter/Mimo) | Manual API key creation per agent |
| 1Password | Requires business account |
| Web Search (Gemini, Brave) | New account creation per agent |
| Notion API | Must create integration in personal workspace |
| OpenAI Whisper API | Manual key provisioning |
| Twitter | Google SSO broken, email + CAPTCHA + email code |

## Tech Stack

- **Language**: Rust end-to-end
- **Credential delivery**: MCP-only
- **Blockchain**: Heima parachain (Substrate, EVM-compatible, TEE sidechains)
- **Payment**: x402 stablecoin payment protocol (USDC)
- **Provisioning**: Agent-based browser automation in sandbox
- **Sandbox**: agent-infra/sandbox (Docker)

## References

- Heima Parachain: https://github.com/litentry/heima
- agent-infra/sandbox: https://github.com/agent-infra/sandbox
- Kimi Claw (cloud target, post-MVP): https://www.kimi.com/resources/kimi-claw-introduction
- Current landing page: https://agentvault-site.vercel.app/

## Interview Source

Full deep interview spec with transcript: `.omc/specs/deep-interview-agentkeys.md`
