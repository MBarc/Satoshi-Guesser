# Satoshi Guesser

Every spin generates a random Bitcoin private key and checks if it unlocks one of Satoshi's wallets. The odds are about 1 in 10⁷⁷. It runs free on GitHub Actions, 24 hours a day, across 20 parallel workers — no server, no cloud bill.

If it ever hits, your Discord gets a private message with the key. Nobody else sees it.

---

## Fork it and run it yourself

You don't need to change any code. Fork the repo, add your Discord webhook URL as a secret, and kick off the workflow. That's the whole setup.

**Keep your fork public.** GitHub only gives unlimited free Actions minutes to public repos. Private repos cap out at 2,000 minutes a month, which won't last a day.

### Setting up the webhook secret

In your forked repo, go to Settings, then Secrets and variables, then Actions. Create a new secret named `WEBHOOK_URL` and paste your Discord webhook URL as the value.

If you don't have a Discord webhook yet: open any Discord channel, go to Edit Channel, find Integrations, and create a new webhook. Copy the URL it gives you.

### Starting the workflow

Go to the Actions tab, select "Satoshi Guesser," and click Run workflow. The 20 workers start up within a minute and re-trigger themselves every 6 hours automatically.

---

## What it actually does

Each worker pulls a cryptographically random 256-bit number and treats it as a Bitcoin private key. From that it derives a public key using secp256k1 elliptic curve math, runs it through SHA-256 and RIPEMD-160 to get a hash, then encodes that into a Bitcoin address. The address gets checked against a local list of ~22,000 addresses tied to the Patoshi mining pattern — the wallets widely attributed to Satoshi.

All of this runs inside the GitHub runner. No external API calls, no blockchain queries. Just math.

---

## Why GitHub Actions

Running 20 parallel jobs on GitHub's infrastructure costs nothing for public repos. Each job runs for just under 6 hours before the next scheduled trigger fires and spins up a fresh batch. Across all workers you get roughly 3 to 4 billion keys checked per day.

Hits go only to your webhook URL, which GitHub stores as an encrypted secret. Nothing useful gets written to the public logs.

<!-- STATS -->
Total keys checked: **0**
Last updated never
<!-- /STATS -->

---

## The odds

```
Keyspace:       2^256  ~  1.16 x 10^77
Keys per day:          ~  3.5  x 10^9
Time to cover 1%:      ~  10^65 years
```

This is not a serious attack on Bitcoin. It's a demonstration of why the keyspace being astronomically large is the whole point. Random guessing at this scale is not a threat — it's the reason Bitcoin works.

---

## Stack

- [noble/curves](https://github.com/paulmillr/noble-curves) and [noble/hashes](https://github.com/paulmillr/noble-hashes) for the cryptography
- Node.js 20 on GitHub-hosted Ubuntu runners
- Address list sourced from [SatoshiGuesser](https://github.com/Pathos0925/SatoshiGuesser)

---

## Rotating your webhook

```
gh secret set WEBHOOK_URL --body "your-new-url"
```

Or update it through Settings if you prefer the UI.
