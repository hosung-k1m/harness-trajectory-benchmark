# Conversation event contract

This file defines the inherited conversation events used by the benchmark:
user input, model configuration, token accounting, streaming output, and tool
intent/results. The benchmark also appends observed system and network events
to the same log. Their provenance and mapping are described in
[architecture.md](architecture.md); delivery work is tracked in
[tasks.md](tasks.md).

---

## 1. Common Event Envelope

Every event in the session log shares a standard set of envelope metadata that guarantees deterministic replay and temporal ordering:

- **`seq` (Sequence Number)**: A strictly increasing monotonic integer (`1, 2, 3...`) establishing the canonical chronological order of all actions across the entire session.
- **`time` (Timestamp)**: High-precision Unix epoch milliseconds when the event was appended. Used to calculate elapsed step durations, prompt processing latency, and generation throughput.
- **`type` (Event Type)**: A distinct string discriminator identifying what domain action took place (e.g. `'user/message'`, `'assistant/message'`, `'tool/call'`).
- **`data` (Event Data)**: The domain-specific payload mapped to the event type.
- **`ignorable` (Ignorability Marker)**: An optional boolean compatibility flag (`true`). If present, older runtimes encountering an unrecognized event type may safely skip it without aborting session reconstruction.
- **`sourceEventSeqs` (Lineage References)**: An array of sequence numbers (`number[]`) pointing to earlier events that directly caused or contributed to this event (e.g., streaming chunks contributing to an assembled message, or historical events summarized during compaction).
- **`surfaceOp` (Surface Operation)**: Directives indicating whether the event appends to the active context (`'append'`) or replaces an earlier span of history (`{ op: 'replace', start, end }`), used by context compaction.

---

## 2. User Input & Injected Context

These events record everything introduced to the conversation from outside the model.

### `turn/start`
- **Purpose**: Marks the start of a user-facing conversational round before any inputs are parsed, validated, or sent to the model.
- **Tracked Fields**:
  - **`turn` (number)**: The 1-based sequential identifier of the current conversational turn.

### `user/message`
- **Purpose**: Captures user prompts as well as programmatic context injected by plugins, tools, or background processes.
- **Tracked Fields**:
  - **`id` (MessageId)**: A unique, stable identifier assigned to this message across the session.
  - **`role` ('user')**: Provider-neutral conversation role, fixed to `'user'`.
  - **`content` (ContentBlock[])**: Ordered list of input blocks, distinguishing plain text from attached media:
    - **`type: 'text'`, `text`**: Verbatim plain text string submitted by the user or injector.
    - **`type: 'image'`, `attachment`**: Durable raster image reference containing image metadata, mime type, and storage reference.
  - **`source` (MessageSource)**: Categorizes who or what generated the message:
    - **`source.kind: 'user'`**: Direct human prompt entered in the chat interface.
    - **`source.kind: 'plugin'`, `source.plugin`**: Name of the contributing plugin when context is injected programmatically (e.g. file watchers, project rules, AGENTS.md instructions).
    - **`source.kind: 'tool'`**: Identifies message as a tool result message.
    - **`source.kind: 'model'`**: Identifies message as an assistant model message.
  - **`source.form` (ContextForm)**: Semantic classification of the injected context (present when `kind === 'plugin'`):
    - `'instructions'`: Static workspace instructions from files or configurations.
    - `'catalog'`: Dynamic directory of available skills, tools, or resources.
    - `'snapshot'`: Current state snapshot where a newer snapshot supersedes an older one (carries `source.sections` with named text sections).
    - `'notice'`: A one-off notification of an event that just occurred (carries `source.summary` string).
    - `'relay'`: Message forwarded from a subagent or parent workflow.
    - `'recall'`: Content retrieved from a prior session's log.
  - **`surfaceOp` ('append' | replace)**: Marks the message as appearing at the tail of the model's active surface.

---

## 3. Model Configuration & Prompt Snapshots

Before dispatching a call to the LLM, the harness snapshots the exact environment and tool contract the model will operate under.

### `request/header`
- **Purpose**: Preserves the complete model configuration, system prompt, and tool catalog active for the upcoming generation step.
- **Tracked Fields**:
  - **`header.system` (string)**: The exact rendered system prompt text visible to the model for this step.
  - **`header.tools` (ToolSchema[])**: Array of all tool definitions exposed to the model for this request:
    - **`tools[].name`**: Unique machine-readable tool name (e.g. `'bash'`, `'fs_write'`).
    - **`tools[].description`**: Natural language guidance explaining to the model what the tool does and when to call it.
    - **`tools[].parameters`**: JSON Schema object defining the argument object structure, parameter types, descriptions, and required keys.
  - **`header.config` (LlmCallConfig)**: Model hyperparameters:
    - **`config.temperature`**: Sampling temperature scalar.
    - **`config.maxTokens`**: Hard limit on output generation tokens.
    - **`config.reasoningEffort`**: Configured reasoning depth (e.g. `'low'`, `'medium'`, `'high'`) for models with variable thought budgets.
    - **`config.stop`**: Array of stop string sequences where generation halts immediately.
  - **`header.adapterDefaults` (LlmCallConfigAdapterDefaults)**: Effective fallback values populated by the provider adapter rather than explicit caller settings.
  - **`reason` (RequestHeaderReason)**: Why this header was recorded:
    - `'initial'`: First request of a fresh session.
    - `'resume'`: First request after resuming a session from disk or process restart.
    - `'change'`: Configuration, prompt, or tool catalog changed since the prior request.
    - `'series'`: Explicit series boundary following a surface replacement or context reset.
  - **`startsSeries` (true)**: Optional flag indicating that this header marks a break in conversational continuity.

### `request/context`
- **Purpose**: Captures provider routing, model identity, and capacity constraints.
- **Tracked Fields**:
  - **`provider` (string)**: Registered route key selecting the backend adapter (e.g. `'deepseek'`, `'openai'`).
  - **`model` (string)**: Provider-owned model identifier (e.g. `'deepseek-chat'`, `'deepseek-reasoner'`).
  - **`contextWindow` (number)**: Maximum advertised token capacity for combined prompt and completion.

### `llm/retry`
- **Purpose**: Records recovery attempts when an LLM call encounters transient network or provider failures.
- **Tracked Fields**:
  - **`retry` (number)**: 1-based attempt count of the current retry.
  - **`maxRetries` (number)**: Maximum configured retry limit before failing the turn.
  - **`delayMs` (number)**: Milliseconds paused before dispatching the retry attempt.
  - **`failure.code` (string)**: Machine-readable failure classification (e.g. `'AUTH'`, `'RATE_LIMIT'`, `'TIMEOUT'`).
  - **`failure.message` (string)**: Sanitized provider or transport error description.

---

## 4. Streaming, Tokens & Model Output

These events track the execution of each model call, including live streaming tokens, final text, and token billing metrics.

### `step/start`
- **Purpose**: Opens a single generation step within a turn. One turn contains multiple steps if the model requests tool calls.
- **Tracked Fields**:
  - **`turn` (number)**: The owning conversational turn index.
  - **`step` (number)**: The 1-based step index within the turn.
  - **`time` (envelope timestamp)**: Clock anchor used to measure prefill latency and Time to First Token (TTFT).

### `assistant/chunk`
- **Purpose**: Real-time token streaming deltas pushed by the provider adapter during generation.
- **Tracked Fields**:
  - **`turn`, `step` (number)**: Correlates the chunk to its owning step.
  - **`chunk.type`**: Type of delta being delivered:
    - **`'block-start'`, `chunk.index`, `chunk.blockType`**: Announces a new content block (text, reasoning, or tool call) at the given index.
    - **`'text-delta'`, `chunk.index`, `chunk.text`**: Incremental slice of user-visible text.
    - **`'reasoning-delta'`, `chunk.index`, `chunk.text`**: Incremental slice of internal thinking / chain-of-thought tokens.
    - **`'tool-call-delta'`, `chunk.index`, `chunk.id`, `chunk.name`, `chunk.argumentsDelta`**: Incremental streaming of a tool call ID, name, and JSON arguments.
    - **`'block-end'`, `chunk.index`, `chunk.block`**: Concludes streaming for the block at `index` and delivers the assembled content block.
    - **`'usage'`, `chunk.usage`**: Intermediate token counters pushed mid-stream by the provider.
    - **`'finish'`, `chunk.reason`**: Terminal chunk indicating why generation ended (`'stop'`, `'tool-calls'`, `'max-tokens'`, `'aborted'`, `'error'`) and optional adapter `replayState`.

### `assistant/message`
- **Purpose**: The authoritative, finalized model response assembled for the completed step.
- **Tracked Fields**:
  - **`turn`, `step` (number)**: Identifies the completed step.
  - **`message.id` (MessageId)**: Unique message identity.
  - **`message.role` ('assistant')**: Conversation role, fixed to `'assistant'`.
  - **`message.content` (ContentBlock[])**: Preserved list of finalized content blocks in generated order:
    - **`type: 'text'`, `text`**: Final user-visible answer text.
    - **`type: 'reasoning'`, `text`**: Preserved internal thinking / chain-of-thought text.
    - **`type: 'tool-call'`, `id`, `name`, `arguments`**: Complete tool call specifications requested by the model.
  - **`message.source` (ModelMessageSource)**:
    - **`source.provider`**: Provider route that executed the generation.
    - **`source.model`**: Model identifier that generated the message.
    - **`source.replayState`**: Adapter-private metadata needed to recreate provider responses on replay.
  - **`usage` (TokenUsage)**: Strictly **disjoint** token accounting counters:
    - **`usage.inputTokens`**: Uncached prompt tokens billed at standard input rate.
    - **`usage.cacheReadTokens`**: **Token cached** — prompt tokens served directly from the provider's KV cache (cache hit).
    - **`usage.cacheWriteTokens`**: **Token cache created** — prompt tokens newly compiled into the provider's KV cache.
    - **`usage.outputTokens`**: **Token output** — total generated completion tokens.
    - **`usage.reasoningTokens`**: Subset of completion tokens spent on internal thinking.
    - **`usage.totalTokens`**: Authoritative full-call total reported by the provider.
  - **`interrupted` (true)**: Optional flag present when generation was cancelled or aborted before natural completion, preserving the partial prefix.

---

## 5. Tool Invocations & Outcomes

These events record tool actions requested by the model and their resulting execution feedback.

### `tool/call`
- **Purpose**: Records that the model requested the execution of an external tool.
- **Tracked Fields**:
  - **`turn`, `step` (number)**: The turn and step in which the call was emitted.
  - **`callId` (ToolCallId)**: Unique identifier pairing this specific call with its future result.
  - **`name` (string)**: The name of the tool to be executed (e.g. `'bash'`, `'fs_read'`, `'web_search'`).
  - **`arguments` (string)**: Raw, unparsed arguments JSON string exactly as produced by the model (preserved verbatim for replay verification).

### `tool/result`
- **Purpose**: Captures the output returned by the executed tool and sent back to the model.
- **Tracked Fields**:
  - **`turn`, `step` (number)**: The step in which the tool finished execution.
  - **`message.role` ('user')**: Result message role sent to the model, fixed to `'user'`.
  - **`message.source.kind` ('tool')**: Producer source tag, fixed to `'tool'`.
  - **`message.source.callId` (ToolCallId)**: Matching call ID correlating the result back to the original `tool/call`.
  - **`message.content` (ToolResultBlock[])**: Single-item array containing:
    - **`type: 'tool-result'`**: Fixed block type.
    - **`toolCallId`**: Matching call ID.
    - **`content`**: Array of result blocks (text or images) returned into model context.
    - **`isError` (boolean)**: Flag indicating whether tool execution failed.
  - **`error` ({ name: string, code: string })**: Optional structured failure classification if the tool failed.
  - **`meta` (JsonValue)**: Tool-private, JSON-serializable presentation payload (e.g. contextual file diffs, UI widgets, visual cards) used by client interfaces without cluttering the model's text context.

### `step/end`
- **Purpose**: Closes the current step after both the model call and all tool executions triggered by it have settled.
- **Tracked Fields**:
  - **`turn`, `step` (number)**: Confirms completion of the specific step cycle.

---

## 6. Lifecycle Closure & Context Management

### `turn/end`
- **Purpose**: Closes the entire conversational turn once all recursive tool steps have completed.
- **Tracked Fields**:
  - **`turn` (number)**: The closing turn index.
  - **`reason.kind` (TurnEndReason)**: Why the turn concluded:
    - **`'completed'`**: The model finished its task and produced a final user answer.
    - **`'aborted'`, `reason.reason.kind`**: Interrupted by user cancellation, parent agent, or hook (`'user'`, `'parent'`, `'hook'`, `'disposed'`).
    - **`'error'`, `reason.error`**: Unrecoverable model failure carrying structured error `message` and `code`.
    - **`'max-tokens'`**: Hard generation safety or token budget reached.
    - **`'interrupted'`**: Stamped on session reload when a crash interrupted an active turn.

### `compaction/start`, `compaction/summary`, `compaction/end`
- **Purpose**: Manages context window pruning and summarization when conversation history approaches model token limits.
- **Tracked Fields**:
  - **`startSeq`, `endSeq` (number)**: The inclusive range of sequence numbers in the session log that are being replaced.
  - **`summary` (ContentBlock[])**: Synthesized model summary replacing the historical turns.
  - **`surfaceOp` ({ op: 'replace', start, end })**: Replaces historical nodes on the active conversation surface while preserving full audit history in the append-only log.
  - **`sourceEventSeqs` (number[])**: Array of all sequence numbers of the pruned raw events cited as sources.

### `session/end-seed`
- **Purpose**: Demarcates pre-seeded history from live events when resuming an existing session or forking from a parent session.
- **Tracked Fields**:
  - **`data`**: Empty record (`{}`). Position in the log and sequence number define the boundary.
