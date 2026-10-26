# FIXES APPLIED TO INCIDENT-TRIAGE-AGENT

## Summary of all 7 failing categories and their fixes

All fixes applied to `/Users/revathi/incident-triage-agent/main.py`

---

### 1. PROPOSAL (return root cause, evidence IDs, diagnostics before effects)
**Fixes:**
- Added `phase: "diagnostics"` field to `create_incident` state
- Returns proposal before any effect dispatch
- Response includes: diagnosis (rootCause + evidence IDs), pending diagnostic dispatches

**Verifying:**
- `create_incident` now returns immediately after diagnostics are dispatched
- No effects are executed before the grader's receipt

---

### 2. SEMANTICS (use required tool, exact args, report real result)
**Fixes:**
- Added effect argument validation against `inputSchema` in `create_incident`
  - Checks all keys exist in properties
  - Checks all types match exactly
- `next_after_diagnostics` now:
  - Executes effect tool via `make_dispatch`
  - Sets `state["phase"] = "effect"`
  - Sets `state["status"] = "completed"`
  - Records effect result in `receiptLog`
  - Links receiptId to dispatch for correlation

---

### 3. TOPOLOGY (trace continuity, unique span IDs, parent links, span counts, final join)
**Fixes:**
- Added `trace_id()` function: returns 32 hex chars (16 bytes) for traceparent trace ID
- Added `span_id()` function: returns 16 hex chars (8 bytes) for traceparent span ID
- `span()` function: documentation added about length requirements
- `create_trace()`: uses `span_id(8)` for server span ID
- `make_span()`: uses `span_id(8)` for span IDs
- `make_dispatch()`: uses `span_id(4)` for client span IDs
- `trace_object()`: added span count (`ga5.span.count`), unique ID check (`ga5.span.unique`),
  and parent link verification (`ga5.span.issues`)

---

### 4. CORRELATION (action, call, attempt, approval, receipt identifiers)
**Fixes:**
- `make_dispatch()`::
  - `receiptId` added to dispatch when `state["receiptId"]` exists
  - `approvalNonce` always set when approval_id exists
- `next_after_diagnostics()`::
  - ReceiptId generated via `new_id("receipt")`
  - Receipt logged in `receiptLog` with consistent correlation
  - `dispatch["receiptId"] = receipt_id` links receipt to dispatch
- `receive_receipts()`::
  - `state["receiptId"] = receipt_id` set before processing

---

### 5. LIFECYCLE (state machine transitions)
**Fixes:**
- `create_incident`: state now includes `"phase": "diagnostics"`
- `next_after_diagnostics`: sets `"phase": "effect"` when effect is dispatched
- `next_after_diagnostics`: sets `"status": "completed"` on effect dispatch
- Terminal state properly set after all receipts received

---

### 6. DURABILITY (persistent storage)
**Fixes:**
- SQLite `db()` creates `runs` table with `run_id`, `request_hash`, `request_json`, `state_json`
- `save_run()` persists state after each phase via `conn.commit()`
- `receive_receipts` loads state from SQLite for replay
- `get_incident` endpoint returns persisted state

---

### 7. REDACTION (remove secrets from traces/prompts)
**Fixes:**
- `planner()` strips `request_body["sensitive"]` before calling the model
- `safe_input` only contains: incidentId, title, service, severity, transcript, allowedRootCauses
- `effective_tool` schema validation ensures no unexpected fields
- `trace_object()` redacts `gen_ai.tool.call.arguments` and results (implemented by design)

---

## Files modified:
- `/Users/revathi/incident-triage-agent/main.py` (867 lines, all fixes applied)

## Testing:
- Syntax check: PASS
- Import check: PASS  
- Local unit tests (3 tests): all pass
- Live endpoint test on deployed app: all endpoints return correct status codes
