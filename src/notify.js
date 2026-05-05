export async function notifyHit(privKeyHex, address, wifUncompressed, wifCompressed) {
  const webhookUrl = process.env.WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn('WEBHOOK_URL not set — hit will not be reported privately');
    return;
  }

  const isDiscord = webhookUrl.includes('discord.com') || webhookUrl.includes('discordapp.com');

  const body = isDiscord
    ? {
        content: '**JACKPOT — Satoshi address matched!**',
        embeds: [
          {
            color: 0xf7931a,
            fields: [
              { name: 'Address', value: `\`${address}\``, inline: false },
              { name: 'WIF (compressed)', value: `\`${wifCompressed}\``, inline: false },
              { name: 'WIF (uncompressed)', value: `\`${wifUncompressed}\``, inline: false },
              { name: 'Raw hex', value: `\`${privKeyHex}\``, inline: false },
            ],
            footer: { text: 'Import a WIF key into Electrum: Wallet → Import Private Keys' },
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
