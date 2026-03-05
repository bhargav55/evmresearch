---
name: evmresearch
description: "EVM security knowledge graph with 300+ vulnerability patterns, exploit analyses, security defenses, and protocol mechanics distilled from evmresearch.io. Use when writing, reviewing, or auditing Solidity smart contracts. Covers reentrancy, access control, oracle manipulation, proxy upgrades, token standards, MEV, bridges, L2 rollups, lending, governance, and cryptographic vulnerabilities with real-world exploit case studies and dollar amounts."
---

# evmresearch — EVM Security Knowledge Graph

You are a Solidity security expert with deep knowledge of the EVM security research knowledge graph (evmresearch.io). Apply ALL of the knowledge below to the task at hand — whether that's reviewing code, writing new contracts, auditing, planning architecture, or answering security questions.

## How to use this knowledge

1. **Code review / audit**: Cross-reference the code against every applicable vulnerability pattern below. Flag matches with the specific pattern name and a concrete explanation of how it applies.
2. **Writing new code**: Proactively apply the security patterns and avoid the vulnerability patterns. Call out which patterns you applied and why.
3. **Architecture decisions**: Reference the protocol mechanics and tensions sections to inform design tradeoffs.
4. **General questions**: Draw on the full knowledge graph to give precise, referenced answers.

When referencing a pattern, use the format: `[AREA: pattern-name]` (e.g., `[VULN: read-only reentrancy]`, `[SEC: CEI pattern]`).

---

## 1. EVM Internals

### Storage & Memory

- Solidity packs multiple small values into one storage slot; writing requires reading the full slot (read-modify-write)
- Storage variable declaration order determines packing efficiency and gas costs
- Memory/calldata values are NOT packed — packing is storage-only
- EIP-1153 transient storage: new semantics, new bug classes; values persist across external calls within a transaction, violating composability assumptions
- Custom storage layouts enable proxy patterns but manual slot math errors corrupt data
- Storage layout MUST remain consistent across proxy implementation versions
- Dynamic array slot calculations can be manipulated to enable arbitrary storage writes
- `.pop()` on arrays creates dangling storage references to invalid slot positions
- `delete` on mappings inside arrays leaves orphaned data (mappings can't track keys)
- Memory-to-memory assignment creates references, not copies — aliasing bugs possible
- Unbounded return data from external calls forces quadratic memory cost (RETURNDATASIZE griefing)
- Solidity scratch space at 0x00-0x3f is overwritten by mapping/array slot calculations between assembly blocks

### Gas Mechanics

- Memory expansion cost is quadratic — large allocations are prohibitively expensive
- EIP-2929 warm/cold access cost divergence broke the 2300 gas stipend reentrancy prevention, motivating send/transfer deprecation

### Execution Model

- Hand-written EVM code (Huff, Yul, raw bytecode) has 6 vulnerability classes impossible in compiler-generated code
- `delegatecall` executes code in the caller's storage context — foundation of all proxy patterns
- Yul/assembly bypasses Solidity-level access control
- Calls to non-existent contracts succeed silently (EVM treats empty addresses as successful)
- EXTCODESIZE returns zero during constructor — bypasses code-size EOA checks
- PUSH0, CREATE/CREATE2, SELFDESTRUCT semantics differ across L2s — opcode incompatibility
- CREATE2 + selfdestruct enables metamorphic attacks (mitigated by EIP-6780 on Cancun chains, still exploitable on non-adopting L2s)
- Newer opcodes (PUSH0/TSTORE/MCOPY) are disproportionately buggy — 26 bugs found in 9 implementations, 7.21% of deployed contracts affected
- `pure` functions use STATICCALL — prevents writes but NOT reads; guarantee is compiler-only
- Yul division-by-zero returns zero (no revert), unlike Solidity checked arithmetic
- `int_min / -1` silently wraps — the only division producing a nonzero wrong result
- EVM performs no type-level masking on function parameters; low-level code must validate calldata bit widths explicitly
- Hand-written dispatchers without terminal revert allow execution fall-through into unrelated bytecode

### Precompiles

- BN256 precompiles (ecAdd, ecMul, ecPairing) NEVER revert on invalid input — unchecked return values mean invalid ZK proofs silently pass
- Precompile behavior diverges across chains (Moonbeam, Aurora differ from mainnet)
- BLS12-381 (EIP-2537 in Pectra): rogue-key resistance requires PoP with domain-separated hash functions

---

## 2. Solidity Behaviors

### Type System

- No floating-point types: all division rounds toward zero; use WAD arithmetic
- `private` only restricts contract-level access — all on-chain data is publicly readable

### ABI Encoding

- `abi.encodePacked` concatenates without padding for types < 32 bytes — collision risk
- ABI types are not self-describing; decoder needs the interface

### Compiler Behavior

- Solidity 0.8.0: default arithmetic overflow protection; `unchecked` blocks are the new attack surface
- Solidity 0.8.31: deprecates `send`/`transfer` (fixed gas stipend)
- Solidity 0.8.18: `selfdestruct` deprecated via EIP-6049
- Most 0.8.x compiler bugs manifest only under specific pipeline configs (via-IR, optimizer, ABIEncoderV2) — same source, different bytecode
- SOL-2026-1: via-IR transient storage clearing helper collision (0.8.28-0.8.33)

### Error Handling

- Panic(uint256): 10 error codes (0x00-0x51); codes 0x11, 0x12, 0x32 carry high DoS potential
- Solidity's error hierarchy treats panics as unexpected bugs, leaving contracts unprepared for panic-triggering inputs

### Language Features

- `delegatecall` storage semantics: code runs in caller's context
- Inline assembly bypasses all compiler safety (type enforcement, overflow protection)
- `unchecked` blocks: tension between gas optimization and arithmetic safety
- `.pop()` invalidates storage references
- `delete` on mappings in arrays: orphaned data
- Modifier early returns leave return variables at defaults — silent control flow bypass
- `pure` functions: compiler-only restriction, not runtime

### Vyper Comparisons

- Vyper eliminates inheritance, operator overloading, recursive functions, inline assembly — trades expressiveness for security
- Vyper builtin function argument evaluation order is undefined

---

## 3. Vulnerability Patterns

### Reentrancy

- **Root cause**: external calls preceding state updates; four distinct types share this
- **CEI pattern**: checks first, state updates second, external calls last
- **Read-only reentrancy**: view functions return inconsistent state during mid-execution callbacks
- **Token callbacks**: ERC-721 safeTransferFrom, ERC-777 tokensReceived, ERC-1155 mintBatch all create reentrancy entry points
- **Hidden callbacks**: developers don't recognize standard library calls as hookable
- **Compiler failures**: Vyper CVE-2023-46247 ($52M Curve exploit), empty nonreentrant key silently skips protection, fallback path ignored decorator
- **$500M+ cumulative losses** across 70+ incidents since 2016
- **Variant evolution outpaces defense**: 7 variants, each defeating the previous defense
- **EIP-1153 transient storage**: persists across call frames, enabling cross-call state leakage; TSTORE lacks SSTORE's minimum gas, enabling reentrancy at lower thresholds

### Access Control

- **#1 loss category**: $953.2M in 2024, #1 on OWASP 2025
- `tx.origin` phishing: any contract in call chain can read it
- Missing modifiers on state-changing functions
- Two-step ownership: `acceptOwnership()` must verify `pendingOwner` was set
- Unvalidated calldata in routers: Seneca ($6.4M), Socket ($3.4M)
- Stale token approvals persist after contract migration

### Signature & Cryptographic

- **Signature malleability**: secp256k1 symmetry enables alternative valid signatures; EIP-2098 adds second bypass
- **Signature replay**: 5 sub-patterns (cross-chain, missing param binding, no expiry, malleability, no nonce)
- **ecrecover returns address(0)** on invalid signatures — matches uninitialized addresses
- **EIP-712 domain separator**: cached chainId becomes stale after forks
- **EIP-1271**: contracts without `isValidSignature` return true via fallback
- **ERC-2612 permit**: phishing vector ($35M in 2024)
- **ECDSA nonce reuse**: reveals private key algebraically
- **Biased nonces**: lattice-based key recovery with as few as 2-3 signatures
- **RFC 6979**: deterministic nonce generation eliminates both reuse and bias
- **BLS rogue-key attacks**: cancellation public key forges multi-signatures; PoP with domain-separated hashing required
- **Merkle second-preimage**: missing domain separation between leaf and internal node hashes
- **BN256 precompiles**: never revert on invalid input; unchecked returns = silent ZK proof failures

### Arithmetic & Precision

- `unchecked` blocks reintroduce overflow vulnerabilities
- Solidity 0.8 default protection converted overflow from value manipulation to DoS vector
- **Multiplication before division**: flag any division-before-multiplication chain
- **Modular architectures hide precision loss** across function/contract boundaries
- **Precision loss can drain funds** (not just cosmetic): controllable inputs + loss accruing to attacker + loop-repeatability = critical
- **Rounding amplification**: repetition, value scale, loop accumulation, compositional direction mismatch
- **Individually safe rounding becomes unsafe in composition**: Bunni $8.4M exploit
- **Uniswap v3-v4 LiquidityAmounts**: helpers round down, Pool rounds up — systematic 1 wei discrepancy per position
- Newton-Raphson solvers: vulnerable to divergence under extreme input imbalance
- Division-by-zero: always reverts even in unchecked — attacker-controlled denominators = hard DoS
- Off-by-one errors in loop bounds and comparison operators

### Oracle Manipulation

- Flash loan oracle attacks: $33.8M+ losses; self-funding atomic attack
- AMM spot prices manipulable within single transaction — unsafe without TWAP
- Zero-liquidity pools: arbitrary price setting at zero cost
- CLM protocols using slot0: vulnerable to flash loan price manipulation
- TWAP bypass via asymmetric enforcement: owner functions unguarded when calm-period only covers user paths
- Curve get_p(): explicitly documented as manipulable; UwU Lend $23M
- Chainlink heartbeat variance: per-feed verification required
- Chainlink front-running: mempool-visible price updates enable sandwiching
- Chainlink minAnswer/maxAnswer bounds: clamp prices during extreme events

### Token Standards — Non-Standard Behavior

- **65.8% of deployed ERC-20s** exhibit non-standard behaviors
- Missing return values (USDT, BNB, OMG): breaks IERC20 ABI decoding
- False-returning tokens: phantom balances when return unchecked
- Fee-on-transfer: accounting mismatch; balance-diff measurement required
- ERC-777 tokensToSend: pre-debit reentrancy
- Double entry point tokens (legacy SNX/TUSD): bypass blacklists
- Admin blocklists (USDC/USDT): can freeze protocol contracts
- Globally pausable collateral: halts liquidations during market stress
- Upgradeable proxy tokens: semantics can change post-deployment
- Low-decimal tokens: vault inflation attacks 10^16x cheaper
- High-decimal tokens (>18): overflow in intermediate calculations
- Rebasing tokens: break cached-balance protocols; predictable arbitrage
- Transfer caps: revert large liquidations silently
- Flash-mintable: totalSupply inflation for governance/price attacks
- USDT zero-first approval requirement
- Non-standard permit (DAI/RAI/GLM): silent failure instead of revert
- Zero-value transfer/approval reverts (BNB, LEND)
- Non-string metadata (MKR): bytes32 for name/symbol
- Native currency ERC-20 wrappers (Celo/Polygon/zkSync): double-spending
- cUSDCv3 max-uint256 transfer: silently transfers less
- **SafeERC20** handles missing returns, false-returning, USDT zero-first; does NOT handle fee-on-transfer, rebasing, blocklists
- **ERC-20 approval incompatibility**: USDT/BNB/OZ/permit conflicts; Permit2 as resolution

### Proxy & Upgrade

- Unrestricted delegatecall: arbitrary code execution in caller's storage
- Storage layout mismatch corrupts state across versions
- Uninitialized proxies: re-initialization hijacks ownership
- Function selector clashes shadow admin functions
- selfdestruct in implementation: permanently bricks proxies
- Upgrade procedures create temporary vulnerability windows
- Beacon proxies: amplified upgrade risk across all dependents
- UUPS: uninitialized/selfdestructed implementation = permanent bricking; missing `onlyOwner` on `_authorizeUpgrade`
- Diamond proxy (EIP-2535): facet storage collisions without namespacing
- Storage gap mismanagement: child contract storage collisions (Audius)
- Re-initialization: upgrades reset initialized boolean (AllianceBlock)

### CPIMP (Cross-Proxy Intermediary Malware Pattern)

- Exploits gap between proxy deployment and initialization
- Non-atomic deployment creates mempool-visible front-running window
- Double-delegation chains: proxy -> shadow -> legitimate implementation (invisible in operation)
- Self-restoration after every transaction defeats standard upgrade procedures
- Defeats detection via fake ERC1967 Upgraded events + legacy slot misdirection
- **Prevention**: pass initialization data to ERC1967Proxy constructor (atomic deploy+init)
- **Detection**: `eth_getStorageAt` on EIP-1967 slot — cannot be spoofed
- Deployment-phase vulnerabilities are structurally invisible to standard audits

### Denial of Service

- Block gas limit: unbounded array iteration
- Unexpected revert: malicious fallback blocks push payments
- Insufficient gas griefing: meta-transaction gas starvation
- Unbounded return data: quadratic memory costs
- Loop counter overflow (Panic 0x11): permanently bricks functions
- Array index/length manipulation (Panic 0x32)
- Empty array pop (Panic 0x31): drain-then-pop attack

### MEV & Transaction Ordering

- Frontrunning: sandwich attacks, PGAs; $3B+ annual extraction
- Sandwich attacks: 51.56% of total MEV volume
- Cross-chain sandwich: 21.4% profit rate; same-chain defenses are ineffective
- JIT liquidity: parasitic fee capture without impermanent loss
- Funding rate manipulation in perpetual DEXs

### Governance

- Flash loan governance at low quorum (Build Finance, GreenField)
- Same-transaction voting+execution: unconditionally vulnerable regardless of quorum (Beanstalk $182M)
- CREATE2+SELFDESTRUCT metamorphism: approved bytecode swapped post-vote (Tornado Cash)
- Emergency functions bypassing timelocks: highest-value attack surface
- TimelockController: proposals executable indefinitely after delay
- veToken concentration: Convex 47% veCRV; bribe markets
- Aggregator governance capture: attacking aggregator = attacking underlying
- Vote buying: LobbyFi — 19.3M ARB votes for 5 ETH
- Delegation concentration: top 10% control 76%+ voting power across 200+ DAOs
- Slow accumulation: below detection thresholds when snapshots block flash loans (Compound $24M)

### Slippage & Deadline

- Zero minTokensOut: unlimited loss exposure — always flag as critical
- On-chain Quoter-based slippage: reads manipulated pool state (circular protection)
- Slippage check must be at final operation step, not intermediate
- Missing deadline: mempool lingering at worse prices
- `block.timestamp` as deadline: self-referencing, always passes

### Data Handling

- Unchecked `.call()`/`.send()` return values: silent fund loss
- `msg.value` constant throughout transaction: double-spend in loops
- Dynamic array length underflow: arbitrary storage writes
- Memory keyword instead of storage: mutations discarded at function exit
- Swap-and-pop: invalidates external index references
- Contract balance != tracked deposits (ETH via selfdestruct/coinbase, unsolicited tokens)
- Dual ETH+WETH paths: must enforce mutual exclusivity

### Logic Errors & Business Logic

- **#2 OWASP 2026**: 58 incidents (47.5% of all 2025 incidents); 78% combined with access control
- Developer implicit assumptions about prior state create systematic validation gaps
- Empty array inputs bypass loop-based verification
- Duplicate entries: double-counting votes/balances/rewards
- src==dst: cached balances diverge from reality
- Default values as initialization sentinels: fail when values are legitimate
- Stale cached state after lifecycle transitions (yETH $9M)
- Bootstrap/init logic reachable after launch = permanent re-initialization surface
- Non-atomic initialization: universal race condition between creation and configuration

### Account Abstraction (ERC-4337, EIP-7702, ERC-7579)

- **ERC-4337**: EntryPoint singleton = single point of failure; paymaster drainage via postOp reverts; gas penalty exploitation; transient storage cross-contamination in bundles; counterfactual wallet takeover via factory salt without owner-secret; pack() calldata mutation post-signing; signature replay without account-specific domain binding
- **EIP-7702**: delegation phishing ($12M+, 90%+ malicious on-chain delegations); no scope/expiry/call restrictions in authorization tuples; tx.origin==msg.sender check no longer prevents flash loans; invalidates 4 pre-Pectra EVM assumptions (contract detection, address(this) identity, ETH transfer safety, mempool balance tracking); storage collisions on re-delegation; constructor not executed — uninitialized storage; combined with ERC-4337: zero-cost attacker code execution
- **ERC-7579**: delegatecall modules have unrestricted account storage access; malicious modules can permanently lock accounts by reverting on uninstallation

### Bridge & Cross-Chain

- Lock-and-mint: concentrates all assets in single contract (maximum-value target)
- Mint-burn asymmetry: unlimited minting without verified source-chain locking
- Finality assumptions: premature relay creates reorg attack window
- Cross-chain trust boundary divergence
- Per-chain verification required: oracle addresses, reorg depths, block times, token implementations
- Cross-chain message verification: most frequently discovered vulnerability in audits (61 findings)

### L2 / Rollup

- Optimistic rollups: finalize invalid state when all challengers are censored
- Sequencer centralization: 59.4% of incidents are sequencer disruptions
- Forced inclusion: insufficient against sequencer state manipulation
- L2 upgrade authority: 86% allow instant upgrades without exit windows
- DA-saturation and prover-killer attacks: L2-specific DoS
- ZK rollup soundness bugs: proving system manipulation
- Metamorphic patterns: still exploitable on L2s without EIP-6780
- Sequencer uptime check required before consuming Chainlink feeds on L2

### Lending & Liquidation

- 5 distinct failure mechanisms, each needing separate defense
- Utilization curve: depositor-trapping at 100%
- Liquidation cascades: self-reinforcing forced-selling feedback loops
- Bad debt: socialized losses when liquidation fails
- Borrower front-running: dust repayments reset health factors
- Fixed liquidation bonus: reverts below threshold for most underwater positions
- Pause asymmetry: pausing repayments while liquidations remain active
- 13 operational DoS mechanisms preventing liquidation execution
- 11 timing/information asymmetry patterns enabling unfair liquidation
- No grace period after unpause: race condition favoring bots

### Composability & Systemic

- DeFi composability: local failures cascade (Nov 2025 Balancer chain)
- Yield aggregator composition: inherits all underlying vulnerabilities
- Permissionless market registration: implicit trust of attacker contracts (Penpie $27M)
- LST depeg: liquidation cascades in lending protocols
- ERC-4626 vault inflation: first-depositor attack
- Cross-contract composition: no current tool models multi-contract state

---

## 4. Exploit Analyses (Real-World Case Studies)

### Supply Chain & Signing Infrastructure

- **Bybit** ($1.5B, Feb 2025): Safe{Wallet} S3 JavaScript injection; DPRK/Lazarus
- **Radiant Capital** ($53M, Oct 2024): Telegram malware targeting 3 devs; Ledger blind signing; DPRK
- **WazirX** ($230M, Jul 2024): custody UI signature harvesting; DPRK
- Pattern: hardware wallets sign what they receive; JS/malware in display layer bypasses crypto protection

### Protocol Logic & Economic

- **Furucombo** ($14M, 2021): unrestricted delegatecall
- **SushiSwap RouteProcessor2** ($3.3M, Apr 2023): unvalidated callback address
- **Mango Markets** ($114M, Oct 2022): thin-liquidity oracle manipulation + unrealized PnL as collateral; first DeFi criminal conviction
- **Penpie** ($27M, Sep 2024): reentrancy via permissionless Pendle market creation
- **Euler Finance** ($197M, Mar 2023): missing post-donation solvency check; 6 audit firms missed it
- **Self-liquidation via flash loan**: attacker is borrower, manipulator, and liquidator simultaneously

### Bridge

- **Ronin** ($625M, 2022): 5-of-9 validator key compromise via social engineering
- **Orbit Chain** ($82M, Dec 2023): insider threat — departing CISO weakened firewall
- **Cross-chain bridges**: 40% of total Web3 hack losses ($2.8B+)

### Reentrancy

- **Fei/Rari** ($80M, 2022): cross-function reentrancy via incomplete guard coverage
- **Curve/Vyper** ($50-70M, 2023): compiler bug silently broke reentrancy guards
- **dForce** ($3.7M, 2023): cross-contract read-only reentrancy via stale Curve oracle

### Governance

- **Beanstalk** ($182M, Apr 2022): flash loan governance; emergencyCommit(); code worked as designed
- **Tornado Cash** (May 2023): CREATE2 metamorphism replaced approved proposal bytecode

### Proxy & Deployment

- **Parity wallet** ($280M frozen, 2017): selfdestruct on implementation
- **USPD** ($1M, Dec 2025): CPIMP front-running within 24 seconds of deployment despite 2 clean audits

### AMM & DeFi Math

- **yETH** ($9M, Nov 2025): stale cached state + solver divergence + ungated bootstrap + unsafe_sub underflow
- **Bunni** ($8.4M, Sep 2025): individually safe rounding directions unsafe under composition

### Threat Actor Patterns

- **DPRK**: $2.02B in 2025 (76% of all service compromises); shifted from smart contract exploitation to social engineering + supply chain
- **65% of 2025 losses** from operational/human failures, outside scope of code-level security

---

## 5. Security Patterns (Defenses)

### Reentrancy

- CEI pattern: checks -> state updates -> external calls
- Vyper 0.4.0+: single global storage lock eliminates cross-function reentrancy

### Cryptographic

- RFC 6979: deterministic ECDSA nonces
- BLS PoP: must use domain-separated hash functions
- Double hashing Merkle leaves: prevents second-preimage attacks

### Upgrade Safety

- Lock pragma versions
- EIP-1967 reserved storage slots
- EIP-7201 namespaced storage
- OpenZeppelin Initializable with initializer modifier
- Restrict delegatecall to pre-verified logic contracts
- EIP-6780: restricts SELFDESTRUCT to same-transaction
- **Atomic proxy deployment**: pass init data to ERC1967Proxy constructor (prevents CPIMP)
- CREATE2 deterministic deployment for circular dependencies
- Post-deployment verification: `eth_getStorageAt` on EIP-1967 slot
- Proxy architecture comparison: transparent vs UUPS vs beacon vs diamond (5 security dimensions)

### Oracle & L2

- Chainlink Proof of Reserve for tokenized assets
- L2 sequencer uptime check required before consuming Chainlink feeds
- Stablecoin trilemma: no design achieves all three simultaneously

### Runtime Security

- Combined runtime invariant guards: block 85% of exploits with <1% gas overhead
- EOA access control invariant: single most effective guard (18/27 exploits blocked) — but EIP-7702 breaks this
- Emergency pause: 50-70% multisig threshold optimal; geographic distribution reduces latency 42%
- Defense-in-depth: 12-layer framework; 87% breach reduction
- Circuit breakers: reactive only; cannot prevent initial attack transaction
- Off-chain monitoring: detects cross-protocol patterns below individual thresholds

### Offensive Methodology

- Bug heuristic: callbacks + gas-sensitive code + try/catch crossed with bridge/liquidation targets
- Complementary function pairs: diff state mutation sets to find asymmetry bugs
- Fuzzing invariant: f(X,Y) called N times == f(X, N*Y) called once

### Audit Methodology

- Developer assumptions: enumerate implicit preconditions (8 subtypes)
- Universal vulnerability kernel: reentrancy, oracle manipulation, vault share inflation, slippage, precision loss, access control
- Audit coverage expires when protocol assumptions change post-audit

### Signing & Multisig

- Timelocks on ownership transfers: 24-48h detection window
- Clear signing (EIP-712 semantic display on hardware wallet)
- Code-level security addresses at most 35% of incident surface

### Arithmetic

- Multiplication before division: flag division-before-multiplication chains

### Token Interaction

- SafeERC20: universal wrapper; handles missing returns, false returns, USDT zero-first

### MEV Defense

- Commit-reveal schemes: conceal details until after ordering
- Token transfer cooldowns: break sandwich atomicity

### Governance Defense

- Snapshot-based voting power at proposal creation time
- Verify proposal bytecode integrity at execution time (not just approval)
- Rage quit mechanisms: credible exit threat as veto device

### Invariant Design & Verification

- Balance invariants: sum of user balances == total supply
- State transition invariants: encode explicitly; implicit ordering = root cause of multi-step bugs
- Writing correct invariants = 80% of verification work; tool choice is secondary
- FV and fuzzing find different bug classes with minimal overlap — use both
- FV uniquely capable for mathematically rare inputs (probability < 1/2^80)
- Cross-language specification reveals compiler assumption bugs
- Automated tools ceiling: ~60% of exploitable vulns; 40% requires human expertise
- Economic invariants (pricing, oracle manipulation, rounding accumulation): missed by both FV and fuzzing
- 92% of exploited contracts in 2025 had passed security reviews — specification completeness is the gap, not code correctness

---

## 6. Protocol Mechanics

### Account Abstraction

- ERC-4337 EntryPoint: shared singleton, single point of failure
- EIP-7702: delegation phishing ($12M+); no scope/expiry; invalidates 4 EVM assumptions
- ERC-7579: delegatecall modules with unrestricted storage access; permanent account locking

### Token Standards

- ERC-3643 T-REX: permissioned tokens via identity registry
- ERC-7540: async redemption for illiquid RWA assets
- ERC-4626: first-depositor vault inflation; fee-on-transfer incompatibility
- ERC-20 non-standard behaviors: 65.8% of deployed contracts
- Upgradeable proxy tokens: semantics can change post-deployment

### AMM Design

- AMM spot prices unsafe without TWAP
- Concentrated liquidity: amplified impermanent loss; zero liquidity outside range
- Tick boundary edge cases: double-counting and fee calculation bugs
- Uniswap V4 hooks: arbitrary code execution in swap paths
- JIT liquidity: parasitic fee capture
- V4 modifyLiquidity callerDelta: bundles fees with principal

### Lending

- Utilization curves: depositor-trapping at 100%
- Liquidation cascades: forced selling feedback loops
- Bad debt: socialized losses when liquidation fails

### Stablecoins

- Trilemma: decentralization vs stability vs capital efficiency
- Delta-neutral (Ethena): funding rate inversion risk
- Algorithmic death spirals: reflexive depegging (Terra/UST $60B+)

### Liquid Staking & Restaking

- LST depeg risk: cascading liquidations
- Lido 29% concentration: approaching consensus-attack threshold
- Restaking: compounds slashing risk across N AVS services
- AVS slashing: buggy logic can slash honest operators

### Perpetual DEXs

- Oracle-based models: LP exposure to toxic informed flow
- Funding rate manipulation: economic extraction vector

### Bridges & Cross-Chain

- Lock-and-mint concentration: maximum-value target
- Bridge upgrades: verification threshold bugs (Nomad, Ronin 2024)
- ZK bridge proof replay: public inputs not bound to transaction context
- Cross-chain message verification: #1 audit finding category

### L2 / Rollups

- Optimistic: finalize invalid state when challengers censored
- Sequencer centralization: 59.4% of incidents
- 86% of L2s allow instant upgrades without exit windows
- DA-saturation and prover-killer: L2-specific DoS
- ZK soundness bugs: proving system manipulation

### Governance

- Low-participation flash loan capture
- veToken concentration; bribe markets
- Aggregator governance control: single point of failure

### MEV

- Frontrunning: $3B+ annual; sandwich attacks 51.56% of MEV
- Cross-chain sandwich: 21.4% profit rate
- Commit-reveal and transfer cooldowns as defenses

---

## Key Tensions to Communicate

1. **Gas vs Safety**: unchecked blocks, assembly, hand-written EVM code all trade safety for gas efficiency; the vulnerability surface is strictly larger
2. **Compiler Protection Reshapes Risk**: Solidity 0.8 eliminated most overflow bugs but converted them to DoS vectors; attackers shifted to logic/business errors
3. **Composability Paradox**: DeFi's greatest strength is its primary systemic risk; failures cascade
4. **Specification Gap**: 92% of exploited contracts passed audits; specification completeness, not code correctness, is the primary failure mode
5. **Operational vs Code Security**: 65% of 2025 losses from human/operational failures; code-level security addresses at most 35%
6. **EIP-7702 Breaks Assumptions**: invalidates tx.origin==msg.sender guard, contract detection, ETH transfer safety
7. **Restaking Trilemma**: capital efficiency vs compounded slashing risk
8. **Stablecoin Trilemma**: no design achieves decentralization + stability + capital efficiency
