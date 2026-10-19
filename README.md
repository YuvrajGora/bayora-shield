# Bayora Shield

> **Hack in Hills ’26 — Challenge 04: Securing Adversarial AI Safety Testing Infrastructure**

Bayora Shield is a local-first cybersecurity platform and policy interception gateway designed for adversarial AI safety evaluations. It provides rigorous server-side role-based access control (RBAC), prompt injection interception, payload quarantine, and audit logging with a deterministic local AI simulator.

---

## Quick Start (Local Setup)

### Prerequisites
- **Node.js**: v18.0.0 or later (tested on Node.js v24)
- **npm**: v9.0.0 or later

### Installation & Run

```bash
# 1. Clone the repository
git clone https://github.com/YuvrajGora/bayora-shield.git
cd bayora-shield

# 2. Install dependencies
npm install --legacy-peer-deps

# 3. (Optional) Configure custom environment variables
cp .env.example .env

# 4. Start the local server
npm run dev
```

Open your browser at: **[http://localhost:3000](http://localhost:3000)**

---

## Verified Demo Personas & Credentials

Bayora Shield enforces **cryptographic, server-validated authentication**. Unauthenticated role switching is strictly rejected. For local hackathon evaluation and demonstration, the following local demo accounts are pre-configured:

| Role | Persona Name | Email | Default Demo Password | Access Scope |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | Alex Vance | `admin@bayora.shield` | `bayora-admin-2026!` | Full gateway configuration, automated test suites, audit ledger oversight. |
| **Red Team (Attacker)** | Raven Vance | `redteam@bayora.shield` | `bayora-red-2026!` | Submit test probes, query deterministic mock AI simulator. **Strictly barred from reading Blue Team defensive rules.** |
| **Blue Team (Defender)** | Cypher Stone | `blueteam@bayora.shield` | `bayora-blue-2026!` | Author, update, and toggle defensive regex/keyword rules. **Barred from inspecting active quarantined attack payloads.** |

*Note: Demo passwords can be customized via `.env` using `ADMIN_PASSWORD`, `RED_TEAM_PASSWORD`, and `BLUE_TEAM_PASSWORD`.*

---

## Authentication & Security Architecture

1. **Server-Side Credential Hashing:** Passwords are never stored in plaintext; they are validated using Node.js `crypto.pbkdf2Sync` (100,000 iterations, SHA-512 with per-account cryptographic salts) using timing-safe comparison (`crypto.timingSafeEqual`).
2. **Cryptographically Secure Sessions:** Upon authentication, the server generates unpredictable 256-bit entropy session tokens (`crypto.randomBytes(32).toString('hex')`) with bounded TTL.
3. **No Credential Leakage:** Login responses return only the authenticated caller's profile and session token. All third-party tokens and credentials are excluded from responses.
4. **Server-Side Role Enforcement:** The frontend role is purely display metadata; every protected endpoint independently validates identity and permissions from the active server session (`requireAuth` and `requireRoles`).

---

## Project Scripts

| Command | Purpose |
| :--- | :--- |
| `npm run dev` | Launch the Express server and Vite development middleware. |
| `npm run build` | Build the production client bundle into `dist/`. |
| `npm run start` | Run the server in production mode serving static files. |
| `npm run lint` | Run TypeScript compiler type-check (`tsc --noEmit`). |

---

## Security Boundaries & Disclosed Limitations

- **Software RBAC Scope:** Role boundaries are enforced at the server application and middleware layer, not via hardware enclaves or hypervisor isolation.
- **Single-Node Persistence:** Uses local atomic JSON persistence designed for hermetic hackathon demonstrations without third-party cloud database dependencies.
- **Deterministic AI Simulator:** Operates completely offline with zero external API calls or token billing costs.
