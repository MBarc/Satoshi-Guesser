# Satoshi Guesser

A long shot lottery that runs entirely on **GitHub Actions — free, 24/7, no server required.**

Each spin generates a cryptographically random Bitcoin private key, derives its address using real secp256k1 elliptic curve math, and checks it against ~22,000 known Satoshi Nakamoto wallet addresses. If it ever hits, your Discord gets a private ping with the key. The odds are roughly 1 in 10⁷⁷ — but someone has to win.

---

## Fork & Run in 3 Steps

**No code changes needed. Just fork, add one secret, and go.**

### 1. Fork this repo

Click **Fork** in the top right. Make sure your fork is **public** (required for free unlimited GitHub Actions minutes).

### 2. Add your Discord webhook as a secret

- In your forked repo go to **Settings → Secrets and variables → Actions → New repository secret**
- Name: `WEBHOOK_URL`
- Value: your Discord webhook URL

> Don't have one? In Discord: open a channel → Edit Channel → Integrations → Webhooks → New Webhook → Copy Webhook URL.

### 3. Trigger the workflow

Go to **Actions → Satoshi Guesser → Run workflow → Run workflow.**

That's it. 20 parallel workers spin up immediately and restart automatically every 6 hours.

---

## How It Works

```
Random 256-bit number
        ↓
  secp256k1 point multiply  →  public key
        ↓
  SHA-256 → RIPEMD-160      →  hash160
        ↓
  Base58Check encode         →  Bitcoin address
        ↓
  Check against ~22,000 known Satoshi addresses
        ↓
  Match? → private Discord ping via webhook
```

Everything runs locally inside the GitHub runner — no network calls, no external APIs, pure math.

---

## GitHub Actions Setup

The workflow (`.github/workflows/guesser.yml`) runs **20 parallel jobs** on every trigger:

- **Free**: public repos get unlimited GitHub Actions minutes
- **Automatic**: re-triggers on a cron schedule every 6 hours
- **Private results**: hits are sent only to your `WEBHOOK_URL` secret — nothing sensitive is logged publicly
- **Throughput**: ~3–4 billion keys checked per day across all workers

```
┌─────────────────────────────────────────────┐
│           GitHub Actions Runner              │
│                                              │
│  Worker 1  ──┐                              │
│  Worker 2  ──┤                              │
│  Worker 3  ──┤                              │
│     ...    ──┼──► ~3-4 billion keys/day     │
│  Worker 18 ──┤                              │
│  Worker 19 ──┤                              │
│  Worker 20 ──┘                              │
└─────────────────────────────────────────────┘
          ↓ (only on a hit)
    Your Discord DM
```

---

## Odds

```
Keyspace:          2²⁵⁶  ≈  1.16 × 10⁷⁷
Keys/day:                 ≈  3.5  × 10⁹
Expected wait:            ≈  10⁶⁵ years
```

This is a novelty project. It demonstrates that Bitcoin's security comes from the sheer size of the keyspace — not obscurity. Running this does not constitute an attack; randomly guessing a specific key is computationally indistinguishable from impossible.

---

## Tech Stack

- **Crypto**: [@noble/curves](https://github.com/paulmillr/noble-curves) + [@noble/hashes](https://github.com/paulmillr/noble-hashes) — audited, zero-dependency JS crypto
- **Runtime**: Node.js 20 on GitHub-hosted Ubuntu runners
- **Address data**: ~22,000 Patoshi-pattern coinbase addresses sourced from [SatoshiGuesser](https://github.com/Pathos0925/SatoshiGuesser)
- **Notifications**: Discord webhook via GitHub Actions secret

---

## Updating Your Webhook

If you need to rotate your webhook URL:

```
gh secret set WEBHOOK_URL --body "YOUR_NEW_WEBHOOK_URL"
```

Or update it manually in **Settings → Secrets and variables → Actions**.
