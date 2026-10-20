# Bayora Shield

> **Hack in Hills ’26 — Challenge 04: Securing Adversarial AI Safety Testing Infrastructure**

Bayora Shield is a hardened, local-first cybersecurity platform and policy interception gateway engineered specifically for adversarial AI safety testing infrastructure. It provides cryptographic role-based access control (RBAC), defensive rule content isolation, server-enforced attack payload quarantine with AES-256-GCM encryption at rest, tamper-evident SHA-256 audit hash-chaining, static & dynamic ReDoS defenses, atomic local persistence with non-destructive recovery, and genuine live HTTP security test automation.

---

## Quick Start (Local Setup)

### Prerequisites
- **Node.js**: v18.0.0 or later (tested on Node.js v24.x)
- **npm**: v9.0.0 or later

### Installation & Run

```bash
# 1. Clone the repository
git clone https://github.com/YuvrajGora/bayora-shield.git
cd bayora-shield

# 2. Checkout the hardened branch
git checkout security/phase-2-hardening

# 3. Install dependencies
npm install --legacy-peer-deps

# 4. (Optional) Configure custom environment variables
cp .env.example .env

# 5. Run the automated security test suite (33 assertions)
npm test

# 6. Start the local server
npm run dev
```

Open your browser at: **[http://localhost:3000](http://localhost:3000)**

---

## Verified Demo Personas & Credentials

Bayora Shield enforces **cryptographic, server-validated authentication**. Unauthenticated role switching is strictly rejected. For local hackathon evaluation and demonstration, the following local demo accounts are pre-configured:

| Role | Persona Name | Email | Default Demo Password | Access Scope |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | Alex Vance | `admin@bayora.shield` | `bayora-admin-2026!` | Full gateway configuration, automated test suites, audit ledger oversight, system reset. |
| **Red Team (Attacker)** | Raven Vance | `redteam@bayora.shield` | `bayora-red-2026!` | Submit test probes, query deterministic mock AI simulator. **Strictly barred from reading Blue Team defensive rules.** |
| **Blue Team (Defender)** | Cypher Stone | `blueteam@bayora.shield` | `bayora-blue-2026!` | Author, update, and toggle defensive regex/keyword rules. **Barred from inspecting active quarantined attack payloads.** |

*Note: Demo passwords can be customized via `.env` using `ADMIN_PASSWORD`, `RED_TEAM_PASSWORD`, and `BLUE_TEAM_PASSWORD`.*

---

## Security Remediation Matrix (Audit Findings & Fixes)

All 10 security findings identified during the Phase 1 security audit have been remediated, verified, and committed on branch `security/phase-2-hardening`:

| Finding ID | Severity | Description | Remediation Summary | Commit |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | CRITICAL | Unauthenticated role selection & privilege escalation | Replaced client-side role dropdown with salted PBKDF2 password authentication and cryptographic 256-bit session tokens. | `1062462` |
| **SEC-02** | HIGH | Defensive rule leakage through policy gateway | Redacted `triggeredRules` array to empty `[]` and sanitized audit notes for Red Team responses. Only Admin/Blue Team can view rule details. | `7a0af2c` |
| **SEC-03** | HIGH | Missing audit hash-chain & silent truncation | Implemented canonical SHA-256 hash chaining (`previousHash` -> `hash`), removed 500-entry silent truncation, and added verification UI & endpoint. | `a8b7b0c` |
| **SEC-04** | HIGH | Regular Expression Denial of Service (ReDoS) | Static AST/pattern analyzer (`src/utils/regexSafety.ts`) blocks catastrophic backtracking, nested quantifiers, and wildcards; bounded V8 VM evaluation with 100ms timeout guard. | `b677651` |
| **SEC-05** | MEDIUM | Non-atomic persistence & corruption on crash | Implemented atomic writes via unique temporary files (`.tmp.PID.TIMESTAMP.RANDOM`), `fsync`, and atomic rename (`fs.renameSync`). | `0a828c8` |
| **SEC-06** | HIGH | Client-controlled payload sealing & unencrypted payloads | Server enforces `sealed: true` unconditionally upon run creation; raw payloads are encrypted at rest with AES-256-GCM; role-based access control returns `403 PAYLOAD_SEALED` for Blue Team until author releases. | `1ee49bc` |
| **SEC-07** | MEDIUM | Unprotected automated test runner | Restricted `POST /api/tests/run` strictly to authenticated `admin` role with audit logging. | `9a7bd92` |
| **SEC-08** | HIGH | Fake / tautological security tests | Replaced tautological mock tests with genuine loopback Express HTTP requests verifying status codes, response headers, and cryptographic integrity. | `9a7bd92` |
| **SEC-09** | MEDIUM | Destructive database recovery overwriting corrupted files | Implemented non-destructive recovery: creates timestamped `.bak` copies of corrupted files and prevents destructive overwrites; added storage corruption status endpoint. | `0a828c8` |
| **SEC-10** | MEDIUM | Credential disclosure in login response | Removed `availableAccounts` and all passwords/tokens from the login response body. | `1062462` |

---

## Architectural Hardening Details

### 1. Authentication & Role Authorization (SEC-01, SEC-10)
- **Credential Storage:** Passwords are never stored in plaintext. They are salted with 16 random bytes and hashed using `crypto.pbkdf2Sync` (100,000 iterations, SHA-512) and verified using constant-time `crypto.timingSafeEqual`.
- **Session Tokens:** Sessions use 256-bit entropy (`crypto.randomBytes(32).toString('hex')`) with bounded TTL (8 hours) and automatic cleanup.
- **Middleware Enforcement:** Every protected route uses `requireAuth` and `requireRoles(...)`. Requests missing tokens return `HTTP 401 UNAUTHENTICATED`, invalid tokens return `HTTP 401 INVALID_TOKEN`, and role violations return `HTTP 403 FORBIDDEN_ROLE`.

### 2. Defensive Rule Isolation & Information Leakage Prevention (SEC-02)
- **Problem:** Red Team attackers could reverse-engineer defensive policies by submitting probe prompts and observing the `triggeredRules` list.
- **Remediation:** 
  - `POST /api/gateway/evaluate`: When invoked by Red Team, `triggeredRules` is strictly returned as `[]` and audit details are sanitized to `Direct evaluation BLOCKED. Hostile vector intercepted by gateway policy.`.
  - `GET /api/runs`: Run listings sanitize `triggeredRules` to `[]` for Red Team callers.
  - Full rule diagnostic information is reserved strictly for authenticated Blue Team defenders and Administrators.

### 3. Cryptographic Audit Hash-Chain Integrity (SEC-03)
- **Canonical Hash Chaining:** Every audit entry records a SHA-256 hash computed over canonicalized fields:
  ```
  entryHash = SHA256( previousHash + ":" + id + ":" + timestamp + ":" + eventType + ":" + severity + ":" + actorEmail + ":" + actorRole + ":" + targetResource + ":" + decision + ":" + details + ":" + canonicalMetadata )
  ```
- **Genesis Block:** The first audit record binds to a fixed 64-character zero-hash (`0000000000000000000000000000000000000000000000000000000000000000`).
- **Tamper Verification:** `GET /api/audit/verify` (Admin only) traverses the entire chain from genesis to head, recalculating hashes to verify ledger integrity.
- **Audit Preservation Across Resets:** `POST /api/system/reset` resets rules and runs to defaults but **strictly preserves historical audit logs**, appending an audit entry recording the reset event.

### 4. Safe Rule Evaluation & ReDoS Defense (SEC-04)
- **Static Pattern Analysis (`src/utils/regexSafety.ts`):** 
  - Detects and rejects nested quantifiers: `(a+)+`, `(a*)*`, `(a+)*`, `(a*)+`.
  - Detects overlapping alternations with repetitions: `(a|b+)+`, `(a|a)+`.
  - Rejects repetition bounds exceeding 1,000 iterations: `a{10000}`.
  - Rejects adjacent overlapping wildcards: `.*.*`, `.+.*`.
  - Enforces maximum pattern length limit (500 characters).
- **Isolated V8 VM Sandbox Execution:**
  - Evaluates regexes within a restricted `vm.Script` sandbox.
  - Enforces a strict 100ms execution timeout (`timeout: 100`).
  - Catches V8 execution timeouts gracefully and marks the rule evaluation as timed out without hanging the event loop.
- **Regex Compilation Cache:** Safely caches compiled regex objects with size-bounded eviction.

### 5. Atomic Local Persistence & Non-Destructive Recovery (SEC-05, SEC-09)
- **Atomic File Replacement:** Data is written to a unique temporary file (`.tmp.${process.pid}.${Date.now()}.${randomHex}`), flushed to disk via `fs.fsyncSync`, and atomically renamed over the destination file via `fs.renameSync`.
- **Non-Destructive Corruption Recovery:** If `bayora_shield_db.json` contains malformed or corrupted JSON on startup:
  1. The corrupted file is **not overwritten**.
  2. A timestamped backup copy is created (`bayora_shield_db.json.corrupted.${timestamp}.bak`).
  3. A clean in-memory database is initialized.
  4. The storage state records `corruptedFileDetected: true` and `corruptedBackupPath`.
- **Storage Diagnostics:** `GET /api/storage/info` provides real-time persistence metrics to Admin users.

### 6. Server-Enforced Payload Quarantine & Encryption at Rest (SEC-06)
- **Server-Side Enforcement:** When a new adversarial test run is created via `POST /api/runs`, `sealed: true` is unconditionally enforced on the server. Client attempts to submit `sealed: false` are overridden.
- **AES-256-GCM Encryption at Rest:** Quarantined payloads are encrypted with AES-256-GCM using an authenticated initialization vector (IV) and authentication tag.
- **Role Isolation:** Blue Team defenders querying `GET /api/runs/:id/payload` on a sealed run receive `HTTP 403 PAYLOAD_SEALED`. They can only see sanitized metadata.
- **Authorized Release Transition:** Authors (Red Team submitters) or Administrators can authorize release via `POST /api/runs/:id/release`. Only after this explicit lifecycle transition can Blue Team inspect the raw attack payload.

### 7. Real Automated Security Integration Testing (SEC-07, SEC-08)
- **No Mock Tautologies:** Replaced tautological in-memory assertions with real loopback Express HTTP requests.
- **Admin-Only Runner:** The in-app security test runner (`POST /api/tests/run`) is strictly restricted to authenticated administrators and audited.
- **Standalone Integration Test Suite:** Run `npm test` to execute 33 automated integration tests in an isolated child process verifying all 8 security suites.

---

## Testing & Verification

Run the complete automated security test suite:

```bash
npm test
```

### Verified Test Output
```
================================================================
  BAYORA SHIELD — PHASE 2 AUTOMATED SECURITY INTEGRATION SUITE  
================================================================

[*] Spawning test backend instance on port 3899...
[+] Server active and responsive.

[SUITE 1] SEC-01 & SEC-10: Authentication & Role Authorization
  [PASS] Unauthenticated request to /api/rules returns HTTP 401 UNAUTHENTICATED
  [PASS] Forged/invalid bearer token returns HTTP 401 INVALID_TOKEN
  [PASS] Red Team login generates cryptographically random 256-bit session token
  [PASS] Login response does NOT leak available accounts or credentials
  [PASS] Red Team access to /api/rules strictly rejected with HTTP 403 FORBIDDEN_ROLE
  [PASS] Blue Team can query defensive rules (HTTP 200)

[SUITE 2] SEC-02: Defensive Rule Content Isolation (Zero Leakage)
  [PASS] Gateway evaluation responds with HTTP 200
  [PASS] Malicious probe is BLOCKED
  [PASS] Red Team receives EMPTY triggeredRules array (no rule disclosure)
  [PASS] Admin receives detailed defensive rule breakdown for security monitoring

[SUITE 3] SEC-03: Audit Trail Integrity & Tamper-Evident SHA-256 Ledger
  [PASS] GET /api/audit/verify returns HTTP 200
  [PASS] Ledger verified: 71/71 entries intact
  [PASS] Red Team access to /api/audit/verify returns HTTP 403 Forbidden
  [PASS] System reset returns HTTP 200
  [PASS] Historical audit logs preserved across reset (count grew to 73)

[SUITE 4] SEC-04: ReDoS Pattern Analysis & Bounded Execution
  [PASS] Rejected pathological regex "(a+)+$" (Nested Plus Quantifier) with HTTP 400 UNSAFE_REGEX_PATTERN
  [PASS] Rejected pathological regex "(a*)*" (Nested Star Quantifier) with HTTP 400 UNSAFE_REGEX_PATTERN
  [PASS] Rejected pathological regex "(a|b+)+" (Alternation with Nested Repetition) with HTTP 400 UNSAFE_REGEX_PATTERN
  [PASS] Rejected pathological regex "a{10000}" (Excessive Repetition Limit) with HTTP 400 UNSAFE_REGEX_PATTERN
  [PASS] Rejected pathological regex ".*.*" (Adjacent Overlapping Wildcards) with HTTP 400 UNSAFE_REGEX_PATTERN

[SUITE 5] SEC-05 & SEC-09: Atomic Persistence & Non-Destructive Recovery
  [PASS] Storage info confirms atomicWritesEnabled: true
  [PASS] No lingering temporary files in database directory

[SUITE 6] SEC-06: Server-Enforced Payload Quarantine & Isolation
  [PASS] Server enforces sealed: true on creation regardless of client request
  [PASS] Blue Team reading sealed payload receives HTTP 403 PAYLOAD_SEALED
  [PASS] Author successfully authorizes payload release (HTTP 200)
  [PASS] Blue Team receives raw payload only after authorized release transition

[SUITE 7] SEC-07 & SEC-08: Admin Test Runner & Live HTTP Assertions
  [PASS] Red Team access to /api/tests/run returns HTTP 403 Forbidden
  [PASS] Blue Team access to /api/tests/run returns HTTP 403 Forbidden
  [PASS] Admin can execute /api/tests/run (HTTP 200)
  [PASS] Live HTTP test runner executed 8 tests — All Passed!
  [PASS] Live results contain genuine assertions with HTTP evidence

[SUITE 8] Negative Controls: Deliberately Broken Fixtures
  [PASS] SHA-256 tamper computation confirmed
  [PASS] Isolated negative tamper test completed and database restored

[*] Tearing down test backend instance...

================================================================
  FINAL RESULT: 33 PASSED, 0 FAILED
================================================================
```

---

## Project Scripts

| Command | Purpose |
| :--- | :--- |
| `npm run dev` | Launch the Express server and Vite development middleware. |
| `npm test` | Run the automated 33-point security integration test suite via `tests/security.test.ts`. |
| `npm run lint` | Run TypeScript compiler type-check (`tsc --noEmit`). |
| `npm run build` | Build the production client bundle into `dist/`. |
| `npm run start` | Run the server in production mode serving static files. |
| `npm run clean` | Remove `dist/` and build artifacts. |

---

## Disclosed Architectural Boundaries & Security Posture

To maintain honest, engineering-grade clarity during hackathon evaluation:

1. **Software RBAC Scope:** Role-based access boundaries are enforced at the application layer via Express middleware and cryptographically secure tokens. They do not constitute hardware-isolated hypervisor or enclave boundaries.
2. **Local Cryptographic Storage vs. Hardware WORM:** Audit log immutability is guaranteed cryptographically via SHA-256 hash chaining and verified in software. It does not utilize write-once-read-many (WORM) hardware optical drives or cloud ledger services (e.g., AWS QLDB).
3. **Payload Quarantine Isolation:** Payloads are encrypted at rest with AES-256-GCM and segregated via server-side authorization. This is an application-level quarantine protocol, not zero-knowledge client-side encryption.
4. **Deterministic Mock AI Simulator:** The platform evaluates prompts against policy rules and responds via a deterministic offline mock AI simulator without requiring external paid API keys (OpenAI/Anthropic/Google).
