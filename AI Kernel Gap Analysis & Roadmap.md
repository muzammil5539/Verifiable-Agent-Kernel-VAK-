# **Verifiable Agent Kernel (VAK): Comprehensive Architectural Audit and Strategic Roadmap**

> **Project Status (February 10, 2026):** Alpha — ~43% Complete
> 
> **Completed:** Phase 1 (Core Kernel), Phase 2 (Policy Layer), Phase 3 (Memory & Provenance), Phase 4 (Neuro-Symbolic), Security Layer
> 
> **In Progress:** Phase 5 (Ecosystem & Interoperability), Testing Layer

## **1\. Executive Summary and Architectural Philosophy**

This report serves as a definitive architectural audit and strategic execution roadmap for the **Verifiable Agent Kernel (VAK)**. As the Senior Systems Architect and Product Manager overseeing this initiative, I have conducted a rigorous Gap Analysis comparing the provided Minimum Viable Product (MVP) documentation against the stringent requirements of a production-grade, Operating System-like control plane for Artificial Intelligence agents. The VAK represents a fundamental paradigm shift in the orchestration of autonomous systems: moving from the current industry standard of loose, framework-based orchestration (e.g., LangChain, AutoGen) to a kernel-based architecture where agents are treated as untrusted processes requiring strict isolation, resource metering, and cryptographic verification.

The contemporary landscape of AI agent development is characterized by "probabilistic indeterminacy"—systems that act with impressive capability but cannot be audited, constrained, or debugged with certainty. The VAK aims to solve this by wrapping the probabilistic engine (the Large Language Model) in a deterministic envelope (the Rust/WASM Kernel) secured by Attribute-Based Access Control (ABAC) and Neuro-Symbolic verification. This report validates that while the MVP establishes a functional baseline using Rust and WebAssembly, it currently lacks the necessary depth in **preemptive scheduling**, **formal policy verification**, **cryptographic provenance**, and **structured reasoning** to be considered "verifiable" in a mission-critical context.

### **1.1 The Philosophy of the Agent Process**

To understand the identified gaps, one must first accept the core theoretical premise of the VAK: **The Agent is a Process.** In traditional operating system theory, a kernel is responsible for the secure multiplexing of hardware resources—CPU time, memory address space, and I/O devices—among competing processes. The kernel does not concern itself with the "intent" of a process, only its adherence to permission boundaries.

In the VAK, the "Agent" is the process. However, unlike a standard binary process which is deterministic, an Agent Process is probabilistic. This introduces novel architectural challenges:

* **The Halting Problem is Real:** Agents effectively running while(true) loops via recursive prompting are a standard failure mode. The kernel must enforce termination not just via wall-clock time, but via "cognitive effort" (token consumption or compute fuel).  
* **Context is Memory:** For an agent, "RAM" is the context window and the vector store. The kernel must manage the "Virtual Memory" of the agent—swapping context in and out of the active window—ensuring that an agent cannot read memory segments (documents) it is not authorized to access.1  
* **Syscalls are Prompts:** When an agent needs to affect the world (read a file, call an API), it emits a specific token sequence. This is the equivalent of a syscall INT 0x80. The kernel must intercept this "Semantic Syscall," validate it against the ABAC policy, and only then execute the underlying Rust host function.2

### **1.2 The Verifiability Triad**

The architectural target for VAK rests on three non-negotiable pillars of verifiability, which serve as the primary criteria for the Gap Analysis:

1. **Computational Verification (Isolation):** The code executed (WASM) is sandboxed and deterministic. The runtime must survive malicious or buggy agents without crashing the host.3  
2. **Semantic Verification (Reasoning):** The intent (LLM output) is checked against logic constraints (Neuro-Symbolic) before action. The system utilizes logic programming to prove safety invariants.4  
3. **Authorization Verification (Policy):** The action is permitted by a formally verifiable policy engine. We move beyond "if statements" to cryptographic proofs of permission.2

The following sections dissect the current MVP against these pillars, identifying specific gaps in the Rust codebase and proposing concrete remediations leveraging the latest research in the Rust ecosystem, including **Wasmtime** for runtime execution, **Cedar** for policy enforcement, **rs-merkle** for audit trails, and **Crepe/Scallop** for neuro-symbolic reasoning.

## ---

**2\. Deep Gap Analysis: Code vs. Specification**

This section compares the implied state of the MVP (based on standard Rust agent implementations and the provided query) against the required specifications for a robust VAK. The analysis identifies four primary "Gap Zones": Runtime Isolation, Policy Enforcement, Memory Provenance, and Cognitive Reasoning.

### **2.1 The Runtime Gap: From "Execution" to "Preemption"**

The MVP documentation suggests a runtime built on wasmtime, likely initializing a basic Engine and Store for each agent interaction. While this provides basic memory sandboxing, it fails to address the temporal and resource exhaustion attacks inherent to hosting untrusted cognitive code.

#### **2.1.1 Deterministic Preemption and The "Halting" Solution**

**Current MVP State:** The MVP likely relies on standard Rust tokio timeouts or simple loop counters to limit agent execution. This is insufficient because it couples the agent's logic to the host's wall-clock time, making the execution non-deterministic and susceptible to "busy wait" attacks where the agent consumes 100% CPU without yielding.

**Target Specification:** The VAK must implement **Fuel Metering** combined with **Epoch-Based Interruption**. Fuel metering allows the kernel to assign a precise "budget" of WebAssembly instructions to an agent.1 This creates deterministic execution—an agent with 1,000 fuel units will always execute exactly the same distance before trapping, regardless of the underlying hardware speed. However, fuel metering imposes a performance overhead on every instruction.

The research indicates that **Epoch Interruption** is the superior mechanism for high-throughput kernels.7 By configuring the Wasmtime engine with epoch\_interruption(true), the VAK spawns a separate "watchdog" thread (the Ticker) that increments a shared epoch counter. The compiled WASM code checks this counter at loop headers and function entries. This allows the VAK to enforce "Time Slices" (e.g., 50ms per agent) efficiently, mimicking a true preemptive OS scheduler.

**Identified Gap:** The lack of store.set\_epoch\_deadline() and a dedicated background ticker thread in the AgentRuntime struct. Without this, a malicious agent can enter an infinite loop inside a complex computation (e.g., matrix multiplication) and freeze the thread, potentially stalling the entire tokio runtime if the host function call is synchronous.

#### **2.1.2 Memory Isolation and the Pooling Allocator**

**Current MVP State:** Standard Wasmtime usage allocates new memory regions via mmap for every new instance. In a high-density environment where VAK might host hundreds of agents, this leads to significant virtual memory fragmentation and slow startup times.

**Target Specification:** The architecture requires the use of the **Pooling Allocator** strategy.8 This pre-allocates a massive slab of memory at kernel startup and divides it into fixed-size "slots" for agent instances. This enforces a strict physical RAM limit per agent (e.g., 512MB) and reduces instantiation time to microseconds by reusing slots.

**Identified Gap:** Absence of wasmtime::PoolingAllocationStrategy configuration in the MVP. This leaves the host vulnerable to OOM (Out of Memory) attacks where an agent recursively grows its linear memory until the host process is killed by the OS OOM killer.

| Feature | MVP State (Inferred) | Target VAK Architecture | Severity |
| :---- | :---- | :---- | :---- |
| **Execution Limiting** | tokio::time::timeout | **Epoch Interruption & Fuel:** Deterministic traps via store.set\_fuel() and async yielding via store.epoch\_deadline\_async\_yield\_and\_update().7 | **CRITICAL** |
| **Memory Management** | Dynamic mmap allocation. | **Pooled Allocator:** Pre-allocated slots enforcing strict instance limits.8 | **HIGH** |
| **Async Host Calls** | Synchronous or naive blocking. | **Async Stack Switching:** Native integration with tokio to yield the WASM stack when awaiting I/O.9 | **HIGH** |

### **2.2 The Policy Gap: From "Hardcoded Logic" to "Formal Verification"**

The MVP documentation alludes to "ABAC policies," likely implemented as custom Rust structs containing if/else logic or basic JSON pattern matching (e.g., "if role \== 'admin'"). This approach is brittle, difficult to audit, and creates a tight coupling between the kernel code and the business logic.

#### **2.2.1 Decoupled Policy Engine (Cedar)**

**Current MVP State:** Policy logic is embedded in the host function implementation. To change a permission (e.g., "Agents can only access /tmp"), the kernel binary must be recompiled and redeployed.

**Target Specification:** The industry standard for modern authorization is **Cedar Policy**.2 Cedar is a purpose-built language that supports rigorous automated reasoning. By integrating the cedar-policy crate, the VAK can externalize all permission logic into .cedar files. The kernel's job becomes simply to construct a Request object containing the Principal (Agent ID), Action (e.g., fs::read), and Resource (Target File), and query the Cedar engine.

Crucially, Cedar supports **Policy Analysis**.11 Before a new policy set is loaded into the kernel, the VAK can run the Cedar Analyzer to mathematically prove safety invariants, such as "No agent, regardless of role, can ever delete the audit log." This provides a level of security assurance that imperative Rust code cannot match.

**Identified Gap:** The MVP lacks the cedar-policy integration middleware. Specifically, the Linker which binds WASM imports to Rust host functions does not currently contain a generic interception layer to enforce authorization *before* the function logic executes.

#### **2.2.2 Context-Aware Authorization**

**Current MVP State:** Authorization is likely Role-Based (RBAC), checking static attributes like "User Level."

**Target Specification:** VAK requires Attribute-Based Access Control (ABAC) utilizing dynamic context.6 Security decisions for agents must depend on transient state: "Is the system currently under high load?", "Is the agent's confidence score low?", "Has the agent accessed sensitive data recently?". This requires injecting a Context object into the Cedar evaluation engine containing real-time telemetry from the runtime.

| Feature | MVP State (Inferred) | Target VAK Architecture | Severity |
| :---- | :---- | :---- | :---- |
| **Policy Language** | Rust structs / JSON. | **Cedar Policy:** Formally verifiable, separate from code.2 | **CRITICAL** |
| **Enforcement Point** | Inside function logic. | **Linker Middleware:** Intercept calls at the WASM boundary (func\_wrap) before execution begins. | **HIGH** |
| **Context Injection** | Static User Roles. | **Dynamic Context:** Time, GeoIP, TrustScore, SystemAlertLevel injected into every check. | **MEDIUM** |

### **2.3 The Memory Gap: From "Database" to "Cryptographic Provenance"**

The MVP likely uses a standard Vector Database (like Qdrant or pgvector) or a local SQLite file to store agent memory and logs. While functional, this lacks **Provenance**. In a "Verifiable" kernel, we must be able to prove *exactly* what information the agent had access to when it made a decision.

#### **2.3.1 Merkle-Linked Audit Logs**

**Current MVP State:** Logs are mutable text files or database rows. An administrator (or a hacked agent with DB access) could retroactively modify the logs to hide malicious activity.

**Target Specification:** The VAK must implement an **Append-Only Merkle Log**.13 Every action taken by the agent (tool call, thought generation) is hashed, and that hash is combined with the previous entry's hash to form a chain (Merkle DAG). The "Head" hash of this log represents the cryptographic summary of the agent's entire lifecycle. This allows for **Tamper-Evident Logging**: if a single byte of history is altered, the Head hash changes, alerting the verification system.

Research into rs-merkle 13 suggests it is the optimal crate for this, supporting advanced features like sparse Merkle trees which allow for efficient proofs of inclusion (proving an agent *did* see a specific file) without revealing the entire dataset.

#### **2.3.2 Content-Addressable Knowledge Graph**

**Current MVP State:** Memory is unstructured or flat vectors.

**Target Specification:** To support complex reasoning, memory should be structured as a **Content-Addressable Graph (CAG)**.15 Similar to git or IPFS, every piece of data (a memory, a document) is addressed by its hash (CID). This creates a **Knowledge Graph** where relationships between entities are immutable links. The **KotobaDB** project 17 is identified as a reference implementation for this in Rust—a graph-native, version-controlled embedded database that provides "Time Travel" capabilities, allowing developers to fork the agent's memory at a specific point in time to debug a hallucination.

| Feature | MVP State (Inferred) | Target VAK Architecture | Severity |
| :---- | :---- | :---- | :---- |
| **Integrity Model** | Mutable Database. | **Merkle DAG:** Immutable, hash-chained log using rs-merkle.13 | **CRITICAL** |
| **Addressing** | Sequential IDs. | **Content Addressing (CID):** Data retrieval by hash, ensuring duplicate deduplication and verification.15 | **HIGH** |
| **Structure** | Flat Vector List. | **Knowledge Graph:** Entities and relations stored in petgraph or kotoba-db.17 | **MEDIUM** |

### **2.4 The Cognitive Gap: From "Probabilistic" to "Neuro-Symbolic"**

The most significant gap in the MVP is the reliance on the LLM as the sole reasoning engine. LLMs are probabilistic token predictors; they cannot reliably follow negative constraints (e.g., "Do not ever output X").

#### **2.4.1 Neuro-Symbolic Hybrid Architecture**

**Current MVP State:** "Chain of Thought" prompting where the LLM is asked to verify its own plan.

**Target Specification:** The VAK must implement a **Neuro-Symbolic** architecture.4 This involves a hybrid loop:

1. **Neural:** The LLM proposes a plan or fact.  
2. **Symbolic:** A deterministic logic engine (Datalog) validates this plan against a set of invariant rules.

The **Crepe** crate 18 is the ideal Rust native Datalog engine for this. It allows the kernel to define "Physics" for the agent—rules that cannot be broken. For example, if the LLM suggests delete\_file("/etc/hosts"), the Datalog engine runs the rule CriticalFile("/etc/hosts") AND DeleteAction(X) \=\> Violation(X). If crepe derives a Violation, the kernel rejects the action *before* it is ever passed to the execution layer. This provides a mathematical guarantee of safety that prompt engineering cannot achieve.

#### **2.4.2 Constrained Decoding**

**Current MVP State:** Free-text generation parsed via Regex.

**Target Specification:** To make the Neuro-Symbolic bridge efficient, the VAK should utilize **Constrained Decoding**.19 Instead of letting the LLM generate free text, the inference engine is constrained to only output valid Datalog facts or JSON structures that match the kernel's schema. This eliminates the "Parse Error" class of failures and ensures the logic engine always receives valid input.

## ---

**3\. Viability Checklist for Production Readiness**

Before the VAK can be deployed in a high-stakes production environment (e.g., autonomous financial trading, code deployment), it must pass the following rigorous viability gates.

### **3.1 Kernel Stability & Isolation Gates**

* \[x\] **Deterministic Termination:** Does the system pass the "Infinite Loop Test"? An agent containing loop { i \+= 1 } must be terminated by the Epoch Interruption mechanism within \<100ms of the deadline.7 ✅ *Implemented: RT-001, RT-002, RT-006*
* \[x\] **Memory Containment:** Does the PoolingAllocationStrategy successfully prevent a "Memory Bomb" attack? The host process RSS (Resident Set Size) must not exceed the defined quota even when 50 agents try to allocate 4GB each.8 ✅ *Implemented: RT-003*
* \[x\] **Panic Safety:** Is the WASM/Host boundary panic-safe? If a host function panics (e.g., unwrap on a None value), it must be caught via std::panic::catch\_unwind to prevent bringing down the entire VAK node. ✅ *Implemented: RT-005*
* \[x\] **Async Re-entrancy:** Are all host functions fully async and compatible with tokio? Blocking operations in host functions will stall the cooperative scheduler. ✅ *Implemented: RT-004*

### **3.2 Security & Governance Gates**

* \[x\] **Supply Chain Hardening:** Has the codebase been audited with cargo-audit 21 for vulnerability databases and cargo-deny 22 for license compatibility? ✅ *Implemented: SEC-001, SEC-002*
* \[x\] **Unsafe Hygiene:** Has cargo-geiger 23 been run to identify all instances of unsafe Rust? Each instance must be manually reviewed and documented with a // SAFETY: comment explaining the invariant. ✅ *Implemented: SEC-003*
* \[x\] **Default Deny Policy:** Does the Cedar integration fail closed? If the policy file is missing or malformed, the Authorizer must deny all actions. ✅ *Implemented: POL-007*
* \[x\] **Secret Scrubbing:** Does the memory snapshot mechanism automatically redact patterns resembling API keys (e.g., sk-proj-...) before persisting snapshots to disk? ✅ *Implemented: MEM-006*

### **3.3 Interoperability Gates**

* \[x\] **MCP Compliance:** Does the kernel implement the **Model Context Protocol (MCP)**?24 This is critical for ecosystem adoption, allowing the VAK to natively use tools from Anthropic, GitHub, and others without custom adapters. ✅ *Implemented: INT-001, INT-002*
* \[x\] **A2A Handshake:** Can the kernel facilitate an **Agent-to-Agent (A2A)** capability exchange?25 Agent A should be able to query Agent B's interface definition to negotiate a collaboration protocol. ✅ *Implemented: SWM-001*

### **3.4 Observability & Forensics Gates**

* \[x\] **Distributed Tracing:** Is tracing implemented with opentelemetry? Spans should exist for "Inference", "Logic Check", "Policy Eval", and "Tool Exec".26 ✅ *Implemented: OBS-001*
* \[ \] **Cryptographic Replay:** Can a developer take a Merkle Log from a production incident and replay it in a local VAK instance to reproduce the exact state and decision path? ⚠️ *In Progress: OBS-002*
* \[x\] **Cost Accounting:** Does the kernel track Token Usage \+ Fuel Consumed \+ I/O Bytes to generate a precise micro-bill for the agent's execution? ✅ *Implemented: OBS-003*

## ---

**4\. Detailed Implementation Roadmap**

This roadmap transforms the VAK from a theoretical prototype to a hardened "Iron Kernel." It is structured into four phases, prioritizing stability and security before feature expansion.

### **Phase 1: Core Kernel Stability (The "Iron Kernel")** ✅ COMPLETE

**Goal:** A runtime that cannot be crashed, stalled, or exploited by the agent.

*All items in this phase have been implemented.*

1. **Refactor Execution Engine:**  
   * **Architecture:** Move from default wasmtime::Config to a hardened configuration.  
   * **Action:** Enable epoch\_interruption and consume\_fuel. Implement a dedicated EpochTicker thread that sleeps for 10ms and increments the engine's epoch counter.  
   * **Action:** Implement Store::set\_epoch\_deadline(10) to give agents a 100ms budget per thought cycle.  
   * **Research Ref:** 7 (Epochs)1 (Fuel).  
2. **Memory Hardening:**  
   * **Architecture:** Implement the PoolingAllocationStrategy.  
   * **Action:** define InstanceLimits restricting linear memory to 512MB and Table elements to 10,000. This pre-allocates the virtual address space, preventing fragmentation.  
   * **Research Ref:** 8 (Store Limits).  
3. **Async Host Interface (HFI):**  
   * **Architecture:** Redesign the Linker to use async closures.  
   * **Action:** Use linker.func\_wrap\_async for all I/O bound host functions (fs, net). Ensure the AgentState struct implements Send \+ Sync to move across Tokio threads.  
   * **Research Ref:** 9 (Async Host Functions).

### **Phase 2: The Policy Layer (The "Digital Superego")** ✅ COMPLETE

**Goal:** Formal verification of all agent actions.

*All items in this phase have been implemented, including Cedar integration, context injection, and policy hot-reloading.*

1. **Cedar Integration:**  
   * **Architecture:** Add cedar-policy as the authorization middleware.  
   * **Action:** Create a SecurityContext struct in the AgentState.  
   * **Action:** Implement a check\_permission(op: \&str, resource: \&str) helper that converts Rust strings into Cedar EntityUids and queries the Authorizer.  
   * **Action:** Middleware Injection: Wrap every host function in the Linker with a call to check\_permission. If it fails, return a WasmTrap::PermissionDenied.  
   * **Research Ref:**.2  
2. **Context Injection Pipeline:**  
   * **Architecture:** Build a dynamic context collector.  
   * **Action:** When a syscall occurs, capture SystemTime, RequestIP, and AgentReputation. Serialize these into the Cedar Context JSON blob.  
3. **Policy Administration:**  
   * **Architecture:** Hot-reloading of policies.  
   * **Action:** Store .cedar files in the Merkle Log. When the log updates, trigger a reload of the PolicySet in memory using ArcSwap for lock-free updates.

### **Phase 3: The Memory & Provenance Layer (The "Immutable Past")** ✅ COMPLETE

**Goal:** Cryptographic proof of history and state.

*All items in this phase have been implemented, including Merkle DAG, content-addressable storage, and time travel debugging.*

1. **Merkle DAG Implementation:**  
   * **Architecture:** Replace flat logging with rs-merkle.  
   * **Action:** Define a LogEntry struct: { timestamp, previous\_hash, action\_type, payload\_hash, policy\_signature }.  
   * **Action:** On every state change, compute the Sha256 hash of the entry.  
   * **Research Ref:**.13  
2. **Content-Addressable Storage:**  
   * **Architecture:** Integration of sled or rocksdb as the blob store.  
   * **Action:** Store the actual "Thinking" text and "Tool Output" in the KV store using the Merkle Hash as the Key. This ensures de-duplication of identical thoughts/data.  
   * **Research Ref:** 16 (LLM Memory Graph).  
3. **Knowledge Graph Overlay:**  
   * **Architecture:** Use petgraph to build relationships between CIDs.  
   * **Action:** Create edges like (ThoughtHash) \-\> \[Caused\] \-\> (ActionHash). This allows for graph-based traversal of the agent's reasoning chain.

### **Phase 4: The Neuro-Symbolic Cognitive Layer (The "Prefrontal Cortex")** ✅ COMPLETE

**Goal:** Logic-based safety constraints.

*All items in this phase have been implemented, including Datalog integration, constrained decoding, and the neuro-symbolic hybrid loop.*

1. **Crepe (Datalog) Integration:**  
   * **Architecture:** Embed the crepe Datalog runtime.  
   * **Action:** Define the Safety.dl ruleset. Example: Malicious(X) \<- FileAccess(X, "/etc/shadow").  
   * **Action:** Implement a Reasoning host function. The agent passes a proposed plan; the Kernel converts it to Datalog facts, runs crepe, and returns Ok or Err(Violation).  
   * **Research Ref:**.18  
2. **Constrained Decoding Bridge:**  
   * **Architecture:** Force LLM output to match Datalog schema.  
   * **Action:** Use a grammar-based sampler (e.g., kbnf) during the inference call. constrain the output to match Action(Target, Type).  
   * **Research Ref:** 30 (KBNF).

### **Phase 5: Ecosystem & Interoperability** ⚠️ PARTIALLY COMPLETE

**Goal:** Standardized communication.

*MCP Server and A2A Protocol support have been implemented. LangChain and AutoGPT adapters need completion.*

1. **MCP Server Implementation:**  
   * **Action:** Implement the Model Context Protocol 24 to expose the VAK's capabilities to external clients (e.g., an IDE or a Chat UI).  
   * **Action:** Map internal WASM host functions to MCP Tool definitions.  
2. **A2A Protocol Support:**  
   * **Action:** Implement the AgentCard discovery mechanism 25 so VAK agents can find and collaborate with other agents on the network.

## ---

**5\. Granular Task List**

### **Sprint 1: Runtime Foundations**

* \[ \] **T1.1:** Add wasmtime, tokio, cap-std to Cargo.toml.  
* \[ \] **T1.2:** Create src/runtime/config.rs. Implement configure\_engine() setting consume\_fuel(true) and epoch\_interruption(true).  
* \[ \] **T1.3:** Implement src/runtime/ticker.rs. Spawn the background thread that loops and calls engine.increment\_epoch().  
* \[ \] **T1.4:** Define the VakContext struct (the Store data) ensuring it owns the WasiCtx.  
* \[ \] **T1.5:** Write a test case test\_infinite\_loop\_preemption that loads a WASM module with a loop {} and asserts it traps within 100ms.

### **Sprint 2: Policy Engine**

* \[ \] **T2.1:** Add cedar-policy dependency.  
* \[ \] **T2.2:** Create src/policy/schema.cedar. Define Entity: Agent, Entity: Resource, Action: Read.  
* \[ \] **T2.3:** Implement src/policy/enforcer.rs. Function enforce(principal, action, resource) returning Result.  
* \[ \] **T2.4:** Refactor src/host\_funcs/fs.rs. Insert the enforce() call at the very top of the fs\_read implementation.

### **Sprint 3: Cryptographic Memory**

* \[ \] **T3.1:** Add rs-merkle and sha2 dependencies.  
* \[ \] **T3.2:** Create src/memory/dag.rs. Define struct Node { prev\_hash: \[u8; 32\], data\_hash: \[u8; 32\] }.  
* \[ \] **T3.3:** Implement MerkleLog::append(data: Vec\<u8\>) which calculates the new Root Hash.  
* \[ \] **T3.4:** Integrate sled DB. Implement ContentStore::put(data) returning the CID (Content ID).  
* \[ \] **T3.5:** Update the Host struct to append to the Merkle Log after every successful tool execution.

### **Sprint 4: Logic & Reasoning**

* \[ \] **T4.1:** Add crepe dependency.  
* \[ \] **T4.2:** Create src/logic/safety.rs. Use the crepe\! macro to define the SafetyPolicy logic.  
* \[ \] **T4.3:** Implement src/host\_funcs/reasoning.rs. Expose a verify\_plan function to WASM.  
* \[ \] **T4.4:** Write Datalog rules that forbid network access if the RiskScore fact is high.

### **Sprint 5: Interfaces (MCP/A2A)**

* \[ \] **T5.1:** Add mcp-sdk-rs.31  
* \[ \] **T5.2:** Implement src/api/mcp\_server.rs. Bridge incoming JSON-RPC requests to internal VAK actions.  
* \[ \] **T5.3:** Implement src/api/a2a.rs. Create the AgentCard struct serialization.25

## ---

**6\. Detailed Architectural Insights and Context**

### **6.1 The "Time" Problem in Agent Kernels**

A critical insight derived from the gap analysis is the handling of **Time**. In standard computing, time is a passive metric. In the VAK, time is an *adversary*. An agent stuck in a "reasoning loop" (generating endless Chain-of-Thought tokens) is indistinguishable from a crashed process to the user, but it consumes expensive inference credits.

The epoch\_interruption mechanism 7 is not just a performance optimization; it is a **financial firewall**. It decouples the VAK's responsiveness from the agent's behavior. By setting an epoch deadline, the VAK asserts: "You have 50ms to think. If you are not done, you must yield." If the agent is running a long computation, the VAK can use epoch\_deadline\_async\_yield\_and\_update 7 to capture the agent's stack, suspend it, process other high-priority system tasks (like an incoming "Stop" signal from the user), and then resume the agent. This capability—**Preemptive Multitasking for AI**—is what separates a "Script Runner" from a "Kernel."

### **6.2 The Neuro-Symbolic "Safety Valve"**

The integration of crepe (Datalog) 18 addresses the fundamental flaw of LLM agents: **Hallucinated Compliance**. An LLM might say "I will not delete the file," but then generate the code to delete it. A pure LLM-based verifier (Reflexion) is subject to the same probabilistic failure modes.

Datalog provides a **Deterministic Safety Valve**. The logic rules in crepe operate on ground facts.

* Fact: File("/etc/shadow") has attribute Critical.  
* Rule: Deny(Action) \<- Action(Target), File(Target), Attribute(Target, Critical). This logic is immutable and executes outside the neural network. By forcing the agent to propose actions through this logic gate, the VAK creates a "Sandwich Architecture": Neural Proposal \-\> Symbolic Verification \-\> Neural Execution. This architecture is increasingly recognized in research 5 as the only viable path to high-assurance AI.

### **6.3 Security Through Dependency Hygiene**

The VAK sits at the intersection of two dangerous ecosystems: AI (rapidly evolving, experimental code) and Systems (requiring stability). The recommendation to use cargo-audit, cargo-deny, and cargo-geiger 23 is crucial. The Rust ecosystem is generally safe, but "supply chain attacks" via compromised crates are a real threat.

* cargo-deny: Ensures that no dependency uses a license incompatible with your enterprise constraints (e.g., AGPL in a proprietary product).  
* cargo-geiger: Scans dependencies for unsafe blocks. A kernel aiming for "Verification" cannot rely on a dependency that uses unchecked pointer arithmetic, as this invalidates the memory safety guarantees of the entire system.

### **6.4 The "Time Travel" Debugging Model**

By adopting a **Merkle DAG** 13 for memory, the VAK enables a revolutionary debugging workflow. In traditional systems, if an agent fails, you look at textual logs. In VAK, because every state transition is hashed and linked, a developer can take the RootHash of a failed session, spin up a local VAK instance, and "checkout" that hash. This restores the *exact* memory state, vector store indices, and context window of the agent at that moment. The developer can then "Step Forward" one decision at a time to identify exactly where the reasoning logic diverged. This transforms AI debugging from "reading tea leaves" to "engineering forensics."

This report provides the blueprint for building the VAK not just as a tool, but as a foundational piece of infrastructure—a **Trust Engine** for the autonomous future.

#### **Works cited**

1. wasmtime/examples/fuel.rs at main \- GitHub, accessed on February 1, 2026, [https://github.com/bytecodealliance/wasmtime/blob/main/examples/fuel.rs](https://github.com/bytecodealliance/wasmtime/blob/main/examples/fuel.rs)  
2. Tutorial \- Cedar policy language, accessed on February 1, 2026, [https://www.cedarpolicy.com/en/tutorial](https://www.cedarpolicy.com/en/tutorial)  
3. Trap in wasmtime \- Rust, accessed on February 1, 2026, [https://docs.wasmtime.dev/api/wasmtime/enum.Trap.html](https://docs.wasmtime.dev/api/wasmtime/enum.Trap.html)  
4. Prolog: The Next 50 Year 303135253X, 9783031352539 \- DOKUMEN.PUB, accessed on February 1, 2026, [https://dokumen.pub/prolog-the-next-50-year-303135253x-9783031352539.html](https://dokumen.pub/prolog-the-next-50-year-303135253x-9783031352539.html)  
5. Building Intelligent Agents with Neuro-Symbolic Concepts \- Communications of the ACM, accessed on February 1, 2026, [https://cacm.acm.org/research/building-intelligent-agents-with-neuro-symbolic-concepts/](https://cacm.acm.org/research/building-intelligent-agents-with-neuro-symbolic-concepts/)  
6. gatehouse \- Rust \- Docs.rs, accessed on February 1, 2026, [https://docs.rs/gatehouse](https://docs.rs/gatehouse)  
7. Config in wasmtime \- Rust, accessed on February 1, 2026, [https://docs.wasmtime.dev/api/wasmtime/struct.Config.html](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html)  
8. Store in wasmtime \- Rust, accessed on February 1, 2026, [https://docs.wasmtime.dev/api/wasmtime/struct.Store.html](https://docs.wasmtime.dev/api/wasmtime/struct.Store.html)  
9. Async / Await \- PyO3 user guide, accessed on February 1, 2026, [https://pyo3.rs/v0.13.2/ecosystem/async-await](https://pyo3.rs/v0.13.2/ecosystem/async-await)  
10. Implementation of the Cedar Policy Language \- GitHub, accessed on February 1, 2026, [https://github.com/cedar-policy/cedar](https://github.com/cedar-policy/cedar)  
11. Cedar Language, accessed on February 1, 2026, [https://www.cedarpolicy.com/](https://www.cedarpolicy.com/)  
12. Cedar Policy Language (CPL): 2026 Complete Guide \- StrongDM, accessed on February 1, 2026, [https://www.strongdm.com/cedar-policy-language](https://www.strongdm.com/cedar-policy-language)  
13. antouhou/rs-merkle: The most advanced Merkle tree library for Rust \- GitHub, accessed on February 1, 2026, [https://github.com/antouhou/rs-merkle](https://github.com/antouhou/rs-merkle)  
14. Introducing rs-merkle-tree, a modular, high-performance Merkle Tree library for Rust., accessed on February 1, 2026, [https://www.reddit.com/r/rust/comments/1occ7un/introducing\_rsmerkletree\_a\_modular/](https://www.reddit.com/r/rust/comments/1occ7un/introducing_rsmerkletree_a_modular/)  
15. ipld/libipld: Rust IPLD library \- GitHub, accessed on February 1, 2026, [https://github.com/ipld/libipld](https://github.com/ipld/libipld)  
16. llm\_memory\_graph \- Rust \- Docs.rs, accessed on February 1, 2026, [https://docs.rs/llm-memory-graph](https://docs.rs/llm-memory-graph)  
17. kotoba-db \- crates.io: Rust Package Registry, accessed on February 1, 2026, [https://crates.io/crates/kotoba-db](https://crates.io/crates/kotoba-db)  
18. ekzhang/crepe: Datalog compiler embedded in Rust as a procedural macro \- GitHub, accessed on February 1, 2026, [https://github.com/ekzhang/crepe](https://github.com/ekzhang/crepe)  
19. Logically Constrained Decoding \- ACL Anthology, accessed on February 1, 2026, [https://aclanthology.org/2025.mathnlp-main.11/](https://aclanthology.org/2025.mathnlp-main.11/)  
20. Day 40: Constrained Decoding with LLMs \- DEV Community, accessed on February 1, 2026, [https://dev.to/nareshnishad/day-40-constrained-decoding-with-llms-4368](https://dev.to/nareshnishad/day-40-constrained-decoding-with-llms-4368)  
21. Keeping Rust projects secure with cargo-audit 0.18: performance, compatibility and security improvements | Inside Rust Blog, accessed on February 1, 2026, [https://blog.rust-lang.org/inside-rust/2023/09/04/keeping-secure-with-cargo-audit-0.18/](https://blog.rust-lang.org/inside-rust/2023/09/04/keeping-secure-with-cargo-audit-0.18/)  
22. Making cargo-deny the official RustSec frontend? · Issue \#194 \- GitHub, accessed on February 1, 2026, [https://github.com/EmbarkStudios/cargo-deny/issues/194](https://github.com/EmbarkStudios/cargo-deny/issues/194)  
23. Best way to protect a project from supply chain attacks? : r/rust \- Reddit, accessed on February 1, 2026, [https://www.reddit.com/r/rust/comments/wk42vj/best\_way\_to\_protect\_a\_project\_from\_supply\_chain/](https://www.reddit.com/r/rust/comments/wk42vj/best_way_to_protect_a_project_from_supply_chain/)  
24. mcp\_rust\_sdk \- Rust \- Docs.rs, accessed on February 1, 2026, [https://docs.rs/mcp\_rust\_sdk](https://docs.rs/mcp_rust_sdk)  
25. a2a\_types \- Rust \- Docs.rs, accessed on February 1, 2026, [https://docs.rs/a2a-types](https://docs.rs/a2a-types)  
26. Configuring the Rust Tracing Library \- Datadog Docs, accessed on February 1, 2026, [https://docs.datadoghq.com/tracing/trace\_collection/library\_config/rust/](https://docs.datadoghq.com/tracing/trace_collection/library_config/rust/)  
27. Two New Open Source Rust Crates Create Easier Cedar Policy Management \- AWS, accessed on February 1, 2026, [https://aws.amazon.com/blogs/opensource/easier-cedar-policy-management/](https://aws.amazon.com/blogs/opensource/easier-cedar-policy-management/)  
28. rs\_merkle \- Rust \- Docs.rs, accessed on February 1, 2026, [https://docs.rs/rs\_merkle/](https://docs.rs/rs_merkle/)  
29. Crepe: fast, compiled Datalog in Rust \- Reddit, accessed on February 1, 2026, [https://www.reddit.com/r/rust/comments/ikszdg/crepe\_fast\_compiled\_datalog\_in\_rust/](https://www.reddit.com/r/rust/comments/ikszdg/crepe_fast_compiled_datalog_in_rust/)  
30. KBNF: a constrained decoding engine for language models implemented in Rust \- Reddit, accessed on February 1, 2026, [https://www.reddit.com/r/rust/comments/1ewkt5y/kbnf\_a\_constrained\_decoding\_engine\_for\_language/](https://www.reddit.com/r/rust/comments/1ewkt5y/kbnf_a_constrained_decoding_engine_for_language/)  
31. The official Rust SDK for the Model Context Protocol \- GitHub, accessed on February 1, 2026, [https://github.com/modelcontextprotocol/rust-sdk](https://github.com/modelcontextprotocol/rust-sdk)  
32. New methods boost reasoning in small and large language models \- Microsoft Research, accessed on February 1, 2026, [https://www.microsoft.com/en-us/research/blog/new-methods-boost-reasoning-in-small-and-large-language-models/](https://www.microsoft.com/en-us/research/blog/new-methods-boost-reasoning-in-small-and-large-language-models/)  
33. Comparing Rust supply chain safety tools \- LogRocket Blog, accessed on February 1, 2026, [https://blog.logrocket.com/comparing-rust-supply-chain-safety-tools/](https://blog.logrocket.com/comparing-rust-supply-chain-safety-tools/)