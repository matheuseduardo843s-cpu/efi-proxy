import express from 'express';
import https from 'https';
import axios from 'axios';
import { verifyWebhookPix, summarizeCob, isValidTxid } from './webhook-verify.js';

const {
  EFI_CLIENT_ID,
  EFI_CLIENT_SECRET,
  EFI_CERTIFICATE_BASE64, // opcional (P12 em base64)
  EFI_CERT_PEM,           // opcional (certificado PEM completo)
  EFI_KEY_PEM,            // opcional (chave privada PEM completa)
  EFI_SANDBOX = 'true',
  EFI_PIX_KEY,
  PROXY_SECRET,
  WEBHOOK_FORWARD_URL,
  PORT = 3000,
} = process.env;

if (!EFI_CLIENT_ID || !EFI_CLIENT_SECRET || !EFI_PIX_KEY || !PROXY_SECRET) {
  console.error('Missing required env vars (EFI_CLIENT_ID, EFI_CLIENT_SECRET, EFI_PIX_KEY, PROXY_SECRET)');
  process.exit(1);
}

const hasPem = !!(EFI_CERT_PEM && EFI_KEY_PEM);
const hasP12 = !!EFI_CERTIFICATE_BASE64;
if (!hasPem && !hasP12) {
  console.error('Missing certificate: provide either EFI_CERT_PEM + EFI_KEY_PEM, or EFI_CERTIFICATE_BASE64');
  process.exit(1);
}

const isSandbox = EFI_SANDBOX === 'true' || EFI_SANDBOX === '1';
const BASE_URL = isSandbox
  ? 'https://pix-h.api.efipay.com.br'
  : 'https://pix.api.efipay.com.br';

// Normaliza PEM (Render às vezes troca \n literais)
function normalizePem(s) {
  return s.includes('\\n') ? s.replace(/\\n/g, '\n') : s;
}

const agent = hasPem
  ? new https.Agent({
      cert: normalizePem(EFI_CERT_PEM),
      key: normalizePem(EFI_KEY_PEM),
    })
  : new https.Agent({
      pfx: Buffer.from(EFI_CERTIFICATE_BASE64, 'base64'),
      passphrase: '',
    });

console.log(`Efí proxy starting (sandbox=${isSandbox}, auth=${hasPem ? 'PEM' : 'P12'})`);

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

app.get('/', (_, res) => res.json({ ok: true, sandbox: isSandbox, auth: hasPem ? 'PEM' : 'P12' }));

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

    // A Efí já devolve o "copia e cola" na própria cobrança. A imagem vem de
    // uma segunda chamada (/loc/:id/qrcode); se ela falhar, não derrubamos a
    // cobrança — o app gera o QR a partir do copia e cola.
    let qrText = charge.pixCopiaECola || null;
    let qrImage = null;
    if (charge.loc?.id) {
      try {
        const { data: qr } = await axios.get(
          `${BASE_URL}/v2/loc/${charge.loc.id}/qrcode`,
          { httpsAgent: agent, headers: { Authorization: `Bearer ${token}` } }
        );
        qrText = qr.qrcode || qrText;
        qrImage = qr.imagemQrcode || null;
      } catch (e) {
        console.error('qrcode fetch error:', e.response?.data || e.message);
      }
    }
    if (!qrText) {
      return res.status(502).json({ error: 'create_failed', detail: 'Efí não retornou o código PIX' });
    }

    res.json({
      txid: charge.txid,
      status: charge.status,
      qr_code_text: qrText,
      qr_code_image: qrImage,
      expires_at: new Date(Date.now() + expires_seconds * 1000).toISOString(),
    });
  } catch (err) {
    console.error('create error:', err.response?.data || err.message);
    res.status(500).json({ error: 'create_failed', detail: err.response?.data || err.message });
  }
});

// Consulta a cobrança na Efí. Usado pelo status e pela verificação do webhook.
async function fetchCob(txid) {
  const token = await getAccessToken();
  const { data } = await axios.get(
    `${BASE_URL}/v2/cob/${txid}`,
    { httpsAgent: agent, headers: { Authorization: `Bearer ${token}` }, timeout: 10_000 }
  );
  return data;
}

app.get('/pix/status/:txid', requireSecret, async (req, res) => {
  if (!isValidTxid(req.params.txid)) return res.status(400).json({ error: 'invalid_txid' });
  try {
    // paid_cents/original_cents: o webhook do app confere o valor pago contra a cobrança.
    res.json(summarizeCob(await fetchCob(req.params.txid)));
  } catch (err) {
    console.error('status error:', err.response?.data || err.message);
    res.status(500).json({ error: 'status_failed' });
  }
});

// Público (a Efí não manda o X-Proxy-Secret), então NADA do corpo é confiável:
// cada txid é conferido na Efí e só o que está CONCLUIDA é repassado ao app,
// montado a partir da resposta da Efí (ver webhook-verify.js).
app.post('/webhook/pix', async (req, res) => {
  try {
    const { verified, rejected, errors } = await verifyWebhookPix(req.body?.pix, fetchCob);
    // Privacidade: o payload traz nome e CPF/CNPJ do pagador; registra só os identificadores.
    console.log('Webhook Efí recebido:', {
      verified: verified.map((p) => p.txid),
      rejected,
      errors,
    });

    if (verified.length > 0 && WEBHOOK_FORWARD_URL) {
      try {
        await axios.post(WEBHOOK_FORWARD_URL, { pix: verified }, {
          headers: { 'X-Proxy-Secret': PROXY_SECRET, 'Content-Type': 'application/json' },
          timeout: 10_000,
        });
      } catch (e) {
        // Erro em vez de 200: a Efí reenvia o webhook (o processamento é idempotente).
        console.error('forward error:', e.message);
        return res.status(502).json({ received: false });
      }
    }
    if (errors.length > 0) return res.status(502).json({ received: false });
    res.json({ received: true });
  } catch (err) {
    console.error('webhook error:', err.message);
    res.status(500).json({ received: false });
  }
});
app.post('/webhook/pix/', (req, res, next) => { req.url = '/webhook/pix'; app.handle(req, res, next); });

app.listen(PORT, () => console.log(`Efí proxy listening on ${PORT}`));
