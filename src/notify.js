export async function notifyHit(privKeyHex, address, wifUncompressed, wifCompressed) {
  const webhookUrl = process.env.WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn('WEBHOOK_URL not set — hit will not be reported privately');
    return;
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

  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) console.error(`Webhook failed: ${res.status} ${res.statusText}`);
  } catch (err) {
    console.error('Webhook error:', err.message);
  }
}
