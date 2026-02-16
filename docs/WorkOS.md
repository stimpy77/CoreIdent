# CoreIdent Planning Docs Amendment — WorkOS Gap Analysis

## Context

CoreIdent is an open-source .NET OAuth 2.0/OIDC toolkit. We completed a competitive gap analysis against WorkOS (commercial SaaS identity platform) to ensure our roadmap covers the features that matter. The analysis found that CoreIdent's roadmap covers ~90%+ of WorkOS's identity/auth surface, but identified specific gaps that need to be reflected in the planning documents.

**Your job:** Amend `docs/DEVPLAN.md` and `docs/Project_Overview.md` to incorporate the findings below. Do NOT rewrite these files from scratch — make surgical, targeted additions and edits. Preserve all existing content, formatting conventions, and checklist style.

---

## Files to Modify

1. **`docs/DEVPLAN.md`** (~2154 lines) — The detailed development plan with phased features and task checklists
2. **`docs/Project_Overview.md`** (~724 lines) — High-level project overview including sister project pre-planning, phase summaries, removed items, and future watch list

Do NOT modify `docs/Technical_Plan.md` (it covers Phase 0–1 implementation details only).

---

## Gap Analysis Findings — What to Add

### 1. MCP Auth (OAuth 2.1 Authorization Server for Model Context Protocol)

**What it is:** WorkOS now supports acting as an OAuth 2.1-compatible authorization server for the Model Context Protocol (MCP), enabling fine-grained authorization for AI agent workflows. MCP is the emerging standard (originated at Anthropic, now broadly adopted) for how AI agents connect to external tools and data sources. An MCP-compatible auth server lets applications control what tools/resources AI agents can access on behalf of users.

**Why it matters:** This is the most timely strategic opportunity. CoreIdent already has an OAuth 2.1 foundation — supporting MCP auth is a natural extension. The AI agent market is exploding, competition is still low for MCP auth specifically, and being early positions CoreIdent as the go-to .NET identity toolkit for agentic applications.

**Current state in CoreIdent:** Not mentioned anywhere. The "Removed from Roadmap" table in both docs lists "AI Framework SDK Integrations" as "Premature" and "CIBA for AI Actions" as "Specialized." MCP Auth is fundamentally different from those — it's not an SDK integration or a niche protocol. It's extending the existing OAuth server to comply with MCP's authorization spec.

**Where to add:**

In **DEVPLAN.md**:
- Add as **Feature 3.13: MCP-Compatible Authorization Server** in Phase 3 (OAuth/OIDC Server Hardening). This is the natural home because it extends the OAuth server, and Phase 3 already contains DPoP, RAR, PAR, Token Exchange, and other protocol extensions.
- Feature should include these components/tasks:
  - **Component:** MCP Authorization Metadata Discovery
    - [ ] (L2) Extend `/.well-known/oauth-authorization-server` metadata for MCP compatibility
    - [ ] (L1) Advertise supported MCP authorization capabilities
  - **Component:** Third-Party Client Registration for MCP
    - [ ] (L3) Support dynamic registration of MCP clients (tool servers)
    - [ ] (L2) Define default restricted scopes for MCP tool access
  - **Component:** Consent & Delegation for Agent Access
    - [ ] (L3) Scoped consent UI for agent/tool authorization ("App X wants Agent Y to access Z on your behalf")
    - [ ] (L3) Token scoping to limit agent capabilities per-session
    - [ ] (L2) Support for audience-restricted tokens targeting specific MCP tool servers
  - **Component:** Token Lifecycle for Agent Workflows
    - [ ] (L2) Short-lived access tokens with constrained scopes for agent sessions
    - [ ] (L3) Revocation hooks for agent session termination
  - **Test Case:**
    - [ ] (L3) MCP client can obtain scoped token via authorization code flow
    - [ ] (L3) Agent token is rejected when scope is insufficient for requested tool
    - [ ] (L2) MCP authorization metadata is correctly advertised
  - **Documentation:**
    - [ ] (L1) MCP integration guide with sample agent workflow
    - [ ] (L2) Security considerations for agent authorization
- Update the **TL;DR status table** at the top of DEVPLAN.md to include this feature as 🔲 Planned.
- **Important:** Update the "Removed from Roadmap" table in DEVPLAN.md. The entries for "AI Framework SDK Integrations" and "CIBA for AI Actions" should remain removed, but add a clarifying note that MCP Auth is NOT the same as those removed items. Add a brief parenthetical or footnote: the removed items were about embedding AI SDKs or a niche backchannel protocol, whereas MCP Auth extends the existing OAuth 2.1 server for the MCP authorization specification — a protocol-level concern, not an AI SDK integration.

In **Project_Overview.md**:
- Add MCP Auth to the **Phase 3 deliverables** bullet list (if Phase 3 is listed in the phase summaries section around line 530+).
- Update the **"Removed from Roadmap"** table with the same clarifying note as DEVPLAN.md — "AI Framework SDK Integrations" stays removed, but note that MCP-compatible authorization (Phase 3) is a distinct, protocol-level feature.
- Add **MCP (Model Context Protocol) Authorization** to the **"Future Protocol Watch List"** table (around line 604) with status "Specification Stable" and a note like "Supported via Phase 3 Feature 3.13; extends OAuth 2.1 server for AI agent authorization."

### 2. Expand Risk-Based Authentication (Feature 5.6) — "Radar"-Class Capabilities

**What it is:** WorkOS Radar is a full product providing bot detection, credential stuffing protection, impossible travel detection, device fingerprinting with 20+ signals, dormant account monitoring, free-tier abuse detection, custom blocking/challenge rules, and real-time admin alerts. CoreIdent's Feature 5.6 currently has lightweight placeholder tasks for device fingerprinting, geo-location, and step-up auth.

**Why it matters:** This is a sophisticated engineering product. CoreIdent doesn't need to build a turnkey Radar clone, but the current Feature 5.6 significantly understates the surface area. The feature should be expanded to show the full scope of what risk-based auth entails, while explicitly noting CoreIdent's strategy: provide extensible interfaces and reference implementations, not a proprietary signal-collection engine.

**Where to edit in DEVPLAN.md:**
- Significantly expand **Feature 5.6: Risk-Based Authentication** to cover the full surface area. Keep existing tasks but add new components:
  - **Component:** Credential Stuffing Protection
    - [ ] (L2) Brute-force rate limiting per account
    - [ ] (L3) Leaked credential detection integration (coordinate with Feature 5.7)
    - [ ] (L2) Progressive challenge escalation (CAPTCHA → MFA → lockout)
  - **Component:** Bot / Abuse Detection Hooks
    - [ ] (L1) `IRequestClassifier` interface (human / bot / suspicious)
    - [ ] (L2) Pluggable classification provider model
    - [ ] (L1) Default: header/behavior heuristic classifier
  - **Component:** Dormant Account Monitoring
    - [ ] (L1) Track last-active timestamp per user
    - [ ] (L2) Configurable dormancy threshold and policy (alert, disable, require re-verification)
  - **Component:** Free-Tier / Signup Abuse Detection
    - [ ] (L2) Email domain and alias pattern analysis hooks
    - [ ] (L1) Configurable signup rate limits per IP/fingerprint
  - **Component:** Admin Alerting
    - [ ] (L1) `IRiskAlertSink` interface for risk event notifications
    - [ ] (L2) Default implementations: log, webhook, email
  - **Component:** Custom Blocking Rules
    - [ ] (L2) IP range / country / device-based block/challenge rules
    - [ ] (L1) Admin API for managing rules (coordinate with Feature 4.3)
  - Add a **strategy note** at the top of Feature 5.6 (as a blockquote like Feature 3.12 has):
    > **Strategy:** CoreIdent provides extensible risk-assessment interfaces and reference implementations. For teams needing a turnkey fraud/abuse engine with proprietary signal intelligence, integrate a dedicated service (e.g., Castle, Arkose Labs) via the `IRiskScorer` / `IRequestClassifier` hooks. The goal is composability, not competing with dedicated fraud platforms.

In **Project_Overview.md**:
- Expand the **Phase 5 deliverables** bullet for "Risk-Based Authentication" to mention the broader surface area: credential stuffing protection, bot detection hooks, dormant account monitoring, signup abuse detection, admin alerting, and custom blocking rules — all via extensible interfaces.

### 3. Expand Fine-Grained Authorization (Feature 5.2) — Integration Strategy

**What it is:** WorkOS ships a full Zanzibar-style relationship-based authorization engine (FGA) with a Check API, warrant modeling, multi-region redundancy, and 10M operations/month free tier. CoreIdent's Feature 5.2 currently has two bullet items: "FGA/RBAC Hooks (L3)" and "Policy evaluation interface (L2)."

**Why it matters:** Building a Zanzibar-style FGA engine is a multi-year effort and a distraction from CoreIdent's core mission. But the current feature description is too sparse to communicate the deliberate integration strategy. Expand it to show that CoreIdent explicitly enables integration with external FGA engines rather than building one.

**Where to edit in DEVPLAN.md:**
- Expand **Feature 5.2: Fine-Grained Authorization Integration** with:
  - Add a **strategy note** blockquote:
    > **Strategy:** CoreIdent does not aim to build a full authorization engine (Zanzibar/ReBAC). Instead, it provides clean integration points so teams can plug in purpose-built systems like OpenFGA, Cerbos, Ory Keto, SpiceDB, or Warrant. CoreIdent's role is to enrich tokens with the identity and context that authorization engines need, and to provide middleware that bridges authorization decisions into .NET request pipelines.
  - Expand the components:
    - **Component:** Authorization Decision Interface
      - [ ] (L2) `IAuthorizationDecider` interface — check(subject, action, resource) → permit/deny
      - [ ] (L1) Default pass-through implementation
      - [ ] (L2) Middleware to enforce decisions on protected endpoints
    - **Component:** Token Claims Enrichment for Authorization
      - [ ] (L2) Configurable claims that external FGA systems typically consume (roles, groups, org membership, tenant context)
      - [ ] (L1) `IAuthorizationContextProvider` — supply additional context at token issuance
    - **Component:** Reference Integrations
      - [ ] (L2) OpenFGA adapter example
      - [ ] (L1) Documentation: mapping CoreIdent identity model to common FGA relationship schemas
    - **Component:** RBAC Convenience Layer
      - [ ] (L2) Built-in role/permission model for teams that don't need full FGA
      - [ ] (L2) Role-to-scope mapping
      - [ ] (L1) Admin API endpoints for role management (coordinate with Feature 4.3)

In **Project_Overview.md**:
- Update the Phase 5 deliverable bullet from "Fine-grained authorization (FGA/RBAC) integration points" to something more descriptive like "Fine-grained authorization integration — clean hooks for OpenFGA, Cerbos, SpiceDB, etc., plus a built-in RBAC convenience layer for simpler needs."

### 4. Domain Verification (New Feature)

**What it is:** A workflow where enterprise customers prove ownership of their email domain to automatically claim organization membership and enable SSO enforcement. This is a critical B2B SaaS onboarding feature: a customer's IT admin adds a DNS TXT record or uploads a verification file, the system confirms domain ownership, then all users with that email domain are auto-associated with the organization.

**Where to add:**

In **DEVPLAN.md**:
- Add as **Feature 4.5: Domain Verification** in Phase 4 (UI & Administration), since it's a B2B admin/onboarding workflow that ties into multi-tenancy (4.4) and the Admin API (4.3).
  - **Component:** Domain Claim & Verification
    - [ ] (L2) `IDomainVerificationService` interface
    - [ ] (L3) DNS TXT record verification method
    - [ ] (L2) HTTP well-known file verification method
    - [ ] (L2) Store verified domains per tenant/organization
  - **Component:** Automatic Organization Association
    - [ ] (L3) Auto-associate users with matching email domains on login/registration
    - [ ] (L2) Configurable policy: auto-join vs require admin approval
  - **Component:** SSO Enforcement
    - [ ] (L3) Require SSO for verified domain users (block password login)
    - [ ] (L2) Grace period configuration for SSO migration
  - **Test Case:**
    - [ ] (L3) DNS verification succeeds for correct TXT record
    - [ ] (L3) Users with verified domain are associated to organization
    - [ ] (L3) SSO enforcement blocks password login for domain users
  - **Documentation:**
    - [ ] (L1) Domain verification setup guide for B2B SaaS
- Update the **TL;DR status table** at the top with this new feature as 🔲 Planned.

In **Project_Overview.md**:
- Add Domain Verification to the **Phase 4 deliverables** section.
- Mention it in the **Sister project: Enterprise** section's "Realms / multi-tenancy" or as a separate bullet under the high-level feature checklist, since domain verification is a key enterprise onboarding primitive.

### 5. Connected Apps / Post-Auth Account Linking (New Feature)

**What it is:** After a user authenticates, they can link third-party accounts (Slack, GitHub, Jira, Google Drive, etc.) for integration purposes within the SaaS product. This is distinct from "Login with GitHub" (social login for authentication). Connected Apps is about: "Now that you're logged in, connect your GitHub account so we can access your repos on your behalf."

**Where to add:**

In **DEVPLAN.md**:
- Add as **Feature 4.6: Connected Apps (Post-Auth Account Linking)** in Phase 4, since it relates to user portal features (4.2) and requires the OAuth server infrastructure.
  - **Component:** Connected App Registration
    - [ ] (L1) `IConnectedAppProvider` interface
    - [ ] (L2) Store connected app definitions (name, OAuth config, required scopes)
    - [ ] (L1) Admin API for managing connected app definitions (coordinate with Feature 4.3)
  - **Component:** User-Initiated OAuth Linking
    - [ ] (L3) Initiate OAuth 2.0 authorization code flow to third-party service
    - [ ] (L3) Store resulting tokens securely per user per connected app
    - [ ] (L2) Token refresh lifecycle management for connected apps
  - **Component:** User Portal Integration
    - [ ] (L2) "Connected Accounts" section in self-service portal (coordinate with Feature 4.2)
    - [ ] (L2) Connect / disconnect actions
    - [ ] (L1) Display connection status and last-used time
  - **Test Case:**
    - [ ] (L3) User can link external account via OAuth flow
    - [ ] (L3) Disconnecting removes stored tokens
    - [ ] (L2) Token refresh keeps connection alive
  - **Documentation:**
    - [ ] (L1) Connected Apps integration guide
- Update the **TL;DR status table**.

In **Project_Overview.md**:
- Add Connected Apps to Phase 4 deliverables.
- Mention it under **Sister project: Membership + Administration** in the "Self-service UI" section, e.g., "Manage connected third-party accounts (GitHub, Slack, etc.)."

### 6. Update "Removed from Roadmap" — Vault / Feature Flags

**Vault / EKM:** Already listed as removed ("Out of scope; use dedicated tools"). No change needed to the entry itself, but confirm it stays as-is.

**Feature Flags:** WorkOS includes feature flag/rollout capabilities. This is NOT an identity concern. Do NOT add it to the roadmap. Instead, add it to the **"Removed from Roadmap"** table in both docs:

| **Feature Flags / Rollout Control** | Out of scope; not an identity concern. Use dedicated tools (LaunchDarkly, Unleash, Flagsmith, etc.) |

---

## Formatting & Style Rules

1. **Match existing conventions exactly.** DEVPLAN.md uses this structure for features:
   ```
   ### Feature X.Y: Name

   *   **Component:** Name
       - [ ] (LX) Task description
   *   **Test Case:**
       - [ ] (LX) Test description
   *   **Documentation:**
       - [ ] (LX) Doc description
   ```

2. **Blockquote strategy notes** use `>` prefix, like Feature 3.12's goal note.

3. **TL;DR table** at the top of DEVPLAN.md uses this format:
   ```
   | Feature Name | Phase | Feature | Status |
   ```
   New features get `🔲 Planned` status.

4. **Project_Overview.md** phase summaries use bullet lists with bold feature names.

5. **LX levels** follow the legend:
   - L1: Low stakes, easy to fix
   - L2: Moderate stakes, catchable in review
   - L3: High stakes, must be correct

6. **Keep dividers** (`---`) between features consistent with existing pattern.

7. **Cross-references** between features should use the pattern "coordinate with Feature X.Y" in parentheses.

---

## What NOT to Do

- Do NOT rewrite existing features or move them between phases
- Do NOT change any `[x]` (complete) items
- Do NOT modify Phase 0, 1, or 2 content (they are stable/complete)
- Do NOT add Vault, EKM, or Feature Flags to the roadmap (they are correctly out of scope)
- Do NOT build a full FGA engine into the plan — the strategy is integration, not build
- Do NOT remove or modify the "AI Framework SDK Integrations" or "CIBA for AI Actions" removed items — just add the clarifying note about MCP Auth being distinct
- Do NOT modify `docs/Technical_Plan.md`

---

## Summary of Changes

| Doc | Section | Action |
|-----|---------|--------|
| DEVPLAN.md | TL;DR table | Add Feature 3.13, 4.5, 4.6 as 🔲 Planned |
| DEVPLAN.md | Phase 3 | Add Feature 3.13: MCP-Compatible Authorization Server |
| DEVPLAN.md | Phase 4 | Add Feature 4.5: Domain Verification |
| DEVPLAN.md | Phase 4 | Add Feature 4.6: Connected Apps |
| DEVPLAN.md | Feature 5.2 | Expand with strategy note and detailed components |
| DEVPLAN.md | Feature 5.6 | Significantly expand with strategy note and new components |
| DEVPLAN.md | Removed from Roadmap | Add Feature Flags entry; add MCP Auth clarification note |
| Project_Overview.md | Phase 3 summary | Add MCP Auth |
| Project_Overview.md | Phase 4 summary | Add Domain Verification, Connected Apps |
| Project_Overview.md | Phase 5 summary | Expand Risk-Based Auth and FGA descriptions |
| Project_Overview.md | Sister project: Membership | Add Connected Apps mention |
| Project_Overview.md | Sister project: Enterprise | Add Domain Verification mention |
| Project_Overview.md | Future Protocol Watch List | Add MCP Authorization |
| Project_Overview.md | Removed from Roadmap | Add Feature Flags entry; add MCP Auth clarification |
