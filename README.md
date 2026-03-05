# evmresearch

EVM security knowledge graph distilled from [evmresearch.io](https://evmresearch.io) into an [Agent Skill](https://agentskills.io) for AI-assisted Solidity development.

## Install

```bash
npx skills add bhargav55/evmresearch
```

## What it covers

300+ security patterns across 6 knowledge areas:

| Area | Examples |
|------|----------|
| **EVM Internals** | Storage packing, delegatecall, transient storage, precompiles, opcode incompatibility |
| **Solidity Behaviors** | Compiler bugs, unchecked blocks, ABI encoding, error handling |
| **Vulnerability Patterns** | Reentrancy (7 variants), access control, oracle manipulation, proxy/CPIMP, token non-standard behaviors, signature replay, precision loss, MEV, governance, bridges, L2, lending, account abstraction |
| **Exploit Analyses** | 21 real-world case studies with root causes and dollar amounts (Bybit $1.5B, Euler $197M, Beanstalk $182M, etc.) |
| **Security Patterns** | CEI, atomic proxy deployment, runtime invariant guards, audit methodology, formal verification |
| **Protocol Mechanics** | AMM design, lending, stablecoins, restaking, perpetual DEXs, bridges, L2 rollups |

## How agents use it

When activated, the skill instructs the agent to:

- **Code review**: Cross-reference code against all vulnerability patterns, flag matches with pattern names
- **Writing code**: Proactively apply security patterns, call out which defenses were applied
- **Architecture**: Reference protocol mechanics and tradeoff tensions
- **Questions**: Give precise answers referencing specific patterns

Patterns are cited as `[AREA: pattern-name]` (e.g., `[VULN: read-only reentrancy]`).

## Source

Knowledge distilled from [evmresearch.io](https://evmresearch.io) by [kaden.eth](https://x.com/0xKaden).

## License

MIT
