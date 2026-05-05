export async function notifyHit(privKeyHex, address) {
  const webhookUrl = process.env.WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn('WEBHOOK_URL not set — hit will not be reported privately');
    return;
  }

  // Supports Discord webhooks and generic JSON webhooks
  const isDiscord = webhookUrl.includes('discord.com') || webhookUrl.includes('discordapp.com');

  const body = isDiscord
    ? {
        content: '**JACKPOT — Satoshi address matched!**',
        embeds: [
          {
            color: 0xf7931a,
            fields: [
              { name: 'Address', value: `\`${address}\``, inline: false },
              { name: 'Private Key (WIF hex)', value: `\`${privKeyHex}\``, inline: false },
            ],
            footer: { text: 'Import the private key into a wallet immediately.' },
          },
        ],
      }
    : { address, privKeyHex };

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
