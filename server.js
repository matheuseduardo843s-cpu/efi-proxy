import express from 'express';
import https from 'https';
import axios from 'axios';

const {
  EFI_CLIENT_ID,
  EFI_CLIENT_SECRET,
  EFI_CERTIFICATE_BASE64,
  EFI_SANDBOX = 'true',
  EFI_PIX_KEY,
  PROXY_SECRET,
  WEBHOOK_FORWARD_URL,
  PORT = 3000,
} = process.env;

if (!EFI_CLIENT_ID || !EFI_CLIENT_SECRET || !EFI_CERTIFICATE_BASE64 || !EFI_PIX_KEY || !PROXY_SECRET) {
  console.error('Missing required env vars');
  process.exit(1);
}

const isSandbox = EFI_SANDBOX === 'true' || EFI_SANDBOX === '1';
const BASE_URL = isSandbox
  ? 'https://pix-h.api.efipay.com.br'
  : 'https://pix.api.efipay.com.br';

const pfx = Buffer.from(EFI_CERTIFICATE_BASE64, 'base64');
const agent = new https.Agent({ pfx, passphrase: '' });

let tokenCache = { token: null, expiresAt: 0 };

async function getAccessToken() {
  if (tokenCache.token && Date.now() < tokenCache.expiresAt - 30_000) {
    return tokenCache.token;
  }
  const auth = Buffer.from(`${EFI_CLIENT_ID}:${EFI_CLIENT_SECRET}`).toString('base64');
  const { data } = await axios.post(
    `${BASE_URL}/oauth/token`,
    { grant_type: 'client_credentials' },
    {
      httpsAgent: agent,
      headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' },
    }
  );
  tokenCache = { token: data.access_token, expiresAt: Date.now() + data.expires_in * 1000 };
  return data.access_token;
}

const app = express();
app.use(express.json({ limit: '1mb' }));

function requireSecret(req, res, next) {
  if (req.headers['x-proxy-secret'] !== PROXY_SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

app.get('/', (_, res) => res.json({ ok: true, sandbox: isSandbox }));

app.post('/pix/create', requireSecret, async (req, res) => {
  try {
    const { amount_cents, txid, description, payer_name, payer_document, expires_seconds = 3600 } = req.body;
    if (!amount_cents || !txid) return res.status(400).json({ error: 'missing_fields' });

    const token = await getAccessToken();
    const valor = (amount_cents / 100).toFixed(2);

    const body = {
      calendario: { expiracao: expires_seconds },
      valor: { original: valor },
      chave: EFI_PIX_KEY,
      solicitacaoPagador: description || 'Assinatura Zelio MS',
    };
    if (payer_document && payer_name) {
      const doc = payer_document.replace(/\D/g, '');
      body.devedor = doc.length === 11 ? { cpf: doc, nome: payer_name } : { cnpj: doc, nome: payer_name };
    }

    const { data: charge } = await axios.put(
      `${BASE_URL}/v2/cob/${txid}`,
      body,
      { httpsAgent: agent, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }
    );

    const { data: qr } = await axios.get(
      `${BASE_URL}/v2/loc/${charge.loc.id}/qrcode`,
      { httpsAgent: agent, headers: { Authorization: `Bearer ${token}` } }
    );

    res.json({
      txid: charge.txid,
      status: charge.status,
      qr_code_text: qr.qrcode,
      qr_code_image: qr.imagemQrcode,
      expires_at: new Date(Date.now() + expires_seconds * 1000).toISOString(),
    });
  } catch (err) {
    console.error('create error:', err.response?.data || err.message);
    res.status(500).json({ error: 'create_failed', detail: err.response?.data || err.message });
  }
});

app.get('/pix/status/:txid', requireSecret, async (req, res) => {
  try {
    const token = await getAccessToken();
    const { data } = await axios.get(
      `${BASE_URL}/v2/cob/${req.params.txid}`,
      { httpsAgent: agent, headers: { Authorization: `Bearer ${token}` } }
    );
    res.json({ txid: data.txid, status: data.status, paid_at: data.pix?.[0]?.horario || null });
  } catch (err) {
    console.error('status error:', err.response?.data || err.message);
    res.status(500).json({ error: 'status_failed' });
  }
});

app.post('/webhook/pix', async (req, res) => {
  try {
    console.log('Webhook Efí recebido:', JSON.stringify(req.body).slice(0, 500));
    if (WEBHOOK_FORWARD_URL) {
      await axios.post(WEBHOOK_FORWARD_URL, req.body, {
        headers: { 'X-Proxy-Secret': PROXY_SECRET, 'Content-Type': 'application/json' },
        timeout: 10_000,
      }).catch(e => console.error('forward error:', e.message));
    }
    res.json({ received: true });
  } catch (err) {
    console.error('webhook error:', err.message);
    res.json({ received: true });
  }
});
app.post('/webhook/pix/', (req, res, next) => { req.url = '/webhook/pix'; app.handle(req, res, next); });

app.listen(PORT, () => console.log(`Efí proxy listening on ${PORT} (sandbox=${isSandbox})`));
