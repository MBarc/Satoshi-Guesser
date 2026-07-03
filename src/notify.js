const WEBHOOK_BASE_DELAY_MS = 1_000;
const WEBHOOK_MAX_DELAY_MS = 30_000;
// After this many consecutive failures, also dump the key to the log as a
// backup so it survives even if the webhook is permanently broken.
const EMERGENCY_DUMP_AFTER = 10;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Last-resort so a hit is never silently lost. This writes the key to the
// (public) Actions log — but a run with no reachable webhook has no private
// channel anyway, and a logged key beats a lost one.
function dumpKeyToLog(privKeyHex, address, wifUncompressed, wifCompressed) {
  console.error('==================== HIT — EMERGENCY KEY DUMP ====================');
  console.error(`Address:          ${address}`);
  console.error(`Private key hex:  ${privKeyHex}`);
  console.error(`WIF compressed:   ${wifCompressed}`);
  console.error(`WIF uncompressed: ${wifUncompressed}`);
  console.error('Import the WIF into a wallet (e.g. Electrum) and sweep the balance immediately.');
  console.error('=================================================================');
}

// Deliver a hit to the webhook, retrying with exponential backoff until it
// succeeds. Only ever called on a match, so retrying indefinitely is correct:
// this is the one moment the whole project exists for, and the caller must not
// exit until the key is safely delivered. Resolves true once delivered (or,
// if no webhook is configured, once the key has been dumped to the log).
export async function notifyHit(privKeyHex, address, wifUncompressed, wifCompressed) {
  const webhookUrl = process.env.WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn('WEBHOOK_URL not set — falling back to emergency log dump');
    dumpKeyToLog(privKeyHex, address, wifUncompressed, wifCompressed);
    return true;
  }

  const isDiscord = webhookUrl.includes('discord.com') || webhookUrl.includes('discordapp.com');

  const instructions = [
    '1. Download Electrum from electrum.org',
    '2. Create a new wallet → Import Bitcoin Addresses or Private Keys',
    '3. Paste the WIF key below and confirm',
    '4. Send the full balance to a new wallet you control',
  ].join('\n');

  const body = isDiscord
    ? {
        content: '# JACKPOT — Satoshi address matched!',
        embeds: [
          {
            color: 0xf7931a,
            fields: [
              { name: 'Matched Address', value: `\`${address}\``, inline: false },
              {
                name: 'Private Key — Raw Hex (save this)',
                value: `\`${privKeyHex}\``,
                inline: false,
              },
              {
                name: 'WIF Compressed (paste this into Electrum)',
                value: `\`${wifCompressed}\``,
                inline: false,
              },
              {
                name: 'WIF Uncompressed (use if compressed fails)',
                value: `\`${wifUncompressed}\``,
                inline: false,
              },
              { name: 'What to do right now', value: instructions, inline: false },
            ],
            footer: {
              text: 'WIF = Wallet Import Format. It is your private key encoded for wallet software. Do not share it with anyone.',
            },
          },
        ],
      }
    : { address, wifCompressed, wifUncompressed, privKeyHex };

  let attempt = 0;
  let delay = WEBHOOK_BASE_DELAY_MS;
  let dumped = false;

  while (true) {
    attempt++;
    try {
      const res = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        console.log(`Webhook delivered on attempt ${attempt}`);
        return true;
      }
      console.error(`Webhook failed (attempt ${attempt}): ${res.status} ${res.statusText}`);
    } catch (err) {
      console.error(`Webhook error (attempt ${attempt}): ${err.message}`);
    }

    if (!dumped && attempt >= EMERGENCY_DUMP_AFTER) {
      console.error(`Webhook still failing after ${attempt} attempts — emitting emergency log dump as backup`);
      dumpKeyToLog(privKeyHex, address, wifUncompressed, wifCompressed);
      dumped = true;
    }

    await sleep(delay);
    delay = Math.min(delay * 2, WEBHOOK_MAX_DELAY_MS);
  }
}
