# Frontend Requirements

## Purpose

Build a non-expert operator interface for Cyber-security-co-pilot that makes the system's recommendation useful and its blind spots obvious.

This document is derived from:
- [`Sentinel_Value_Proposition.md`](C:/Users/ejtal/Downloads/judgment_drift/Cyber-security-co-pilot/Sentinel_Value_Proposition.md)
- the current backend APIs in [`backend/api/incidents.py`](C:/Users/ejtal/Downloads/judgment_drift/Cyber-security-co-pilot/backend/api/incidents.py)
- the operator action APIs in [`backend/api/operator_actions.py`](C:/Users/ejtal/Downloads/judgment_drift/Cyber-security-co-pilot/backend/api/operator_actions.py)
- the legacy prototype flow that this frontend replaced

## Product Goal

The frontend must help a non-expert answer four questions clearly:

1. What happened?
2. What should I do?
3. What else could I do?
4. Did we check everything?

The frontend should emphasize question 4 more than the current prototype does.

## Core Product Principle

The product is not primarily a chatbot and not primarily a detection dashboard.

The product is a decision screen that:
- recommends an action
- shows alternatives
- makes missing checks visible
- helps a human notice when the system may be incomplete

## Target User

- Non-expert security operator
- May understand alerts and severity labels
- May not understand raw CloudTrail details or control-plane sequences
- Needs to act safely under incomplete information

## Primary Use Cases

1. Review a new incident and understand it in plain language
2. Compare the recommended action to alternatives
3. See which evidence branches were checked vs not checked
4. Decide whether to approve, choose an alternative, ask for more analysis, or escalate
5. Use a double-check flow when the recommendation may be incomplete

## MVP Scope

The frontend MVP must support:

- loading a single incident by `incident_id`
- viewing recommendation and alternatives
- viewing completeness and blind spots
- performing operator actions
- viewing audit feedback after an action
- optional agent Q&A as a secondary tool, not the main workflow

The frontend MVP does not need:

- multi-tenant auth
- polished case queues
- advanced search
- large-scale dashboard analytics
- rich charting

## Information Architecture

The main incident screen must be organized into five sections:

1. Incident Summary
2. Recommended Action
3. Alternatives
4. Coverage and Blind Spots
5. Human Decision and Audit

The agent panel should appear after those sections, not before them.

## Required Screen Structure

### 1. Incident Summary

Must show:
- incident title
- incident ID
- severity / risk band
- affected actor or entity
- short plain-language summary
- short event sequence summary

Must avoid:
- dumping raw JSON as the primary view
- leading with low-level technical fields

### 2. Recommended Action

Must show:
- recommended action label
- why this action is recommended
- whether human approval is required
- priority
- reversibility if available

Must visually distinguish:
- recommendation itself
- justification
- operational caution

### 3. Alternatives

Must show 2-3 alternatives as first-class options, each with:
- label
- reason
- tradeoff
- relative priority if available

Requirements:
- alternatives must be visible without clicking "raw payload"
- the UI must not silently choose the first alternative
- operator must explicitly choose which alternative to act on

### 4. Coverage and Blind Spots

This is the differentiator and must be visually prominent.

Must show:
- completeness level
- warning text if recommendation may be incomplete
- per-category coverage status
- what could change the decision
- missing sources
- double-check candidates

Coverage statuses must distinguish:
- checked and found something
- checked and found nothing
- not checked
- could not check / data unavailable

Do not collapse these states into a generic "warning."

### 5. Human Decision and Audit

Must support these actions:
- Approve recommendation
- Choose alternative
- Ask for more analysis
- Escalate

After action, must show:
- chosen action
- whether double-check was used
- latest recorded decision status

Should also show a lightweight recent audit trail for the current incident.

## Double-Check Flow Requirements

The "Double check" interaction must not be only a button that writes a log.

It must:
- surface missing branches more clearly
- show what evidence is missing
- explain what could change the recommendation
- make safer alternatives easier to compare

Minimum required behavior:
- after clicking double-check, expand a dedicated review area
- show the missing branches and review candidates in a more prominent state
- make "collect more evidence" and "escalate" more obvious choices

## Agent Requirements

The agent is secondary support.

Requirements:
- the agent panel must appear below the primary decision workflow
- the interface must show the current agent mode:
  - production mode
  - local/dev OpenAI session mode
  - mock mode
- the agent must not visually dominate the recommendation and coverage panels

Agent output should be treated as supplemental reasoning, not the canonical decision source.

## Backend Contracts To Use

The frontend should consume these endpoints:

- `GET /incidents/{incident_id}`
- `GET /incidents/{incident_id}/decision-support`
- `GET /incidents/{incident_id}/coverage-review`
- `POST /incidents/{incident_id}/approve`
- `POST /incidents/{incident_id}/alternative`
- `POST /incidents/{incident_id}/escalate`
- `POST /incidents/{incident_id}/double-check`
- `GET` or `POST` to the dedicated agent service for auth status and query

Current dedicated agent endpoints:
- `GET /incidents/{incident_id}/agent-auth`
- `POST /incidents/{incident_id}/agent-query`

## Interaction Requirements

### Incident Loading

The frontend must:
- allow incident ID entry
- handle missing incidents cleanly
- show a loading state
- show a recoverable error state

### Alternative Selection

The frontend must:
- render all alternatives as selectable items
- require explicit selection before sending `POST /alternative`
- show the selected action before final confirmation

### Operator Confirmation

For disruptive actions like credential reset or access lock:
- require explicit confirmation
- show the current completeness warning before submit

### Error States

The frontend must handle:
- backend unavailable
- agent unavailable
- agent quota/auth failures
- partial data availability

The UI should degrade gracefully:
- incident workflow remains usable if agent fails
- recommendation remains visible if agent is unavailable

## Visual Priority Requirements

The screen must prioritize content in this order:

1. Recommendation may be incomplete banner
2. Recommended action
3. Alternatives
4. Coverage status
5. Incident details
6. Agent panel
7. Raw payload

The current prototype overexposes technical/debug content. The next frontend should reverse that.

## Accessibility and Clarity Requirements

- use plain-language labels
- avoid jargon without explanation
- do not require the user to parse JSON to make a decision
- use consistent status wording across the app
- avoid relying on color alone to distinguish coverage states

## Required States For Demo

The frontend must demonstrate at least these scenarios clearly:

1. Complete or mostly complete case
- recommendation appears actionable
- minimal blind-spot warning

2. Incomplete case
- recommendation appears plausible
- network or other branch clearly not checked
- "recommendation may be incomplete" is prominent
- double-check path changes the operator's view of risk

These scenarios already exist in the backend demo data and should be surfaced deliberately.

## Acceptance Criteria

The frontend is acceptable when:

1. A non-expert can explain what happened from the incident screen without opening raw JSON.
2. A non-expert can compare the recommended action to at least two alternatives with visible tradeoffs.
3. The UI clearly distinguishes checked, not checked, and unavailable coverage states.
4. The UI makes "recommendation may be incomplete" impossible to miss in incomplete scenarios.
5. The user can explicitly choose:
- approve
- alternative
- more analysis
- escalate
6. The double-check flow visibly changes the interface state, not just the audit log.
7. Agent failure does not block the main decision workflow.

## Current Prototype Gaps

Compared to the legacy prototype this frontend replaced:

- does not render alternatives as first-class choices with tradeoffs
- silently chooses the first alternative
- under-emphasizes coverage/blind-spot state
- does not make double-check a meaningful second-stage review flow
- places too much emphasis on raw/debug structure relative to operator workflow

## Recommended Next Frontend Work

Implementation should proceed in this order:

1. Replace the current action buttons with a decision card layout
2. Add a dedicated alternatives panel with explicit selection
3. Add a strong completeness/blind-spot banner and category chips
4. Add a real double-check state transition in the UI
5. Keep the agent panel secondary and collapsible

