# ANALYSIS: 7 FAILING CATEGORIES (incident-triage agent)
# All categories scored 0/7
#
# 1. PROPOSAL (return before effects)
#    - create_incident does: plan = normalize_plan(planner(body), body)
#    - Then returns fast with state containing diagnosis + pending diagnostics
#    - CURRENT: response includes diagnosis + dispatches (diagnostics only)
#    - ISSUE: No explicit "proposal" envelope; evidence IDs not in top-level
#    - NEEDS: return rootCause (supported), evidence IDs (required), diagnostics (pre-effect)
#      WITHOUT sending effects. The contract says "before effects".
#
# 2. SEMANTICS (use required tool, exact args, report real result)
#    - make_dispatch(state, tool_name, arguments, phase) creates dispatch
#    - effect dispatched via make_dispatch(state, effect, effect_args, "effect")
#    - ISSUE: effectArguments may contain wrong field names; schema_safe_arguments()
#      strips invalid keys but doesn't fill correctly
#    - ISSUE: when effect is dispatched, the code does NOT actually CALL the tool
#      and return its real result. The dispatch is recorded but no tool execution.
#    - NEEDS: execute the effect tool with exact case-derived args, capture real result
#
# 3. TOPOLOGY (trace continuity, unique span IDs, parent links, span counts, join)
#    - create_trace creates server span -> agent span -> model span -> tools
#    - ISSUE: spans use hex_id(8) = 16 hex chars, but trace context requires
#      8-byte hex (16 chars) for traceId and 4-byte (8 chars) for spanId
#      - Actually hex_id(nbytes) returns nbytes*2 hex chars
#      - traceId needs 16 bytes = 32 hex chars
#      - client_span_id needs 4 bytes = 8 hex chars
#      - The code uses hex_id(8) for both = 16 hex chars for traceId (WRONG)
#    - ISSUE: parent links: make_span(state, name, kind, parent, ...) uses parent
#      as parentId, but the constructor expects parent_id param
#      - The span() function signature: (trace_id, span_id, parent_id, name, kind, ...)
#      - make_span passes parent as parent_id positionally -> OK
#    - ISSUE: get_incident doesn't return span count or join verification
#    - NEEDS: fix span ID lengths, verify parent links, return span counts
#
# 4. CORRELATION (action, call, attempt, approval, receipt IDs)
#    - make_dispatch stores actionId, callId, attempt, approvalId, approval_nonce
#    - ISSUE: make_dispatch generates callId using new_id("call") which includes
#      the prefix and uuid. The code later reuses the same actionId/callId across
#      retries but the receipt nonce is NOT linked to the callId.
#      - set_client_receipt_attrs links receipt to dispatch via _clientSpanId
#      - But policy says: "connect action, call, attempt, approval, and receipt
#        identifiers consistently across spans and logs"
#    - ISSUE: approval objects store approvalId+actionId but not callId/attempt
#    - NEEDS: add receiptId to the dispatch so spans, logs, and receipts all
#      share the same correlation key
#
# 5. LIFECYCLE (state machine transitions)
#    - Status: waiting (create) -> waiting (approval) -> completed/failed (terminal)
#    - ISSUE: no explicit "phase" in state for diagnostics vs effect vs approval
#    - ISSUE: effectDispatched flag set but not reflected in public_state
#    - ISSUE: terminalize only accepts "failed" bool, not phase-level lifecycle
#    - NEEDS: add explicit "phase" field: "diagnostics", "approval", "effect", "terminal"
#      and track lifecycle transitions in the response
#
# 6. DURABILITY (persistent storage)
#    - db() opens SQLite; save_run stores state_json in runs table
#    - ISSUE: save_run stores state AFTER computing response, but if the process
#      crashes AFTER saving but BEFORE returning, the response is lost
#    - ISSUE: no explicit durability checkpoint per phase
#    - NEEDS: persist state at each phase transition (create, approval, effect, terminal)
#
# 7. REDACTION (remove secrets from traces/prompts)
#    - planner() strips request_body["sensitive"] from safe_input
#    - ISSUE: however, the full body is stored in runs.request_json (not redacted)
#    - ISSUE: tool arguments in dispatch may contain secrets if the AI puts them there
#    - ISSUE: trace export (otlp) includes tool arguments/results
#      - The spec says: "omits gen_ai.tool.call.arguments and gen_ai.tool.call.result"
#    - NEEDS: redact sensitive values from request_json, tool arguments, and OTLP
