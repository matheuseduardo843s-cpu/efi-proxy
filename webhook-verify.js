// Verificação do webhook PIX na própria Efí, sem dependências (testável).
//
// O endpoint público /webhook/pix não tem como provar sozinho que o POST veio
// da Efí: o Render encerra o TLS antes do app, então o mTLS do webhook não
// chega aqui. Em vez de confiar no corpo recebido, cada txid é consultado na
// API da Efí (GET /v2/cob/:txid, com o certificado do proxy) e só segue o que
// a Efí diz estar CONCLUIDA, com valor e horário vindos da Efí.

// Formato de txid da Efí/BACEN: 26 a 35 caracteres alfanuméricos.
const TXID_RE = /^[a-zA-Z0-9]{26,35}$/;
// Teto de consultas por POST (evita usar o proxy para martelar a API da Efí).
const MAX_TXIDS = 50;

export function isValidTxid(txid) {
  return typeof txid === 'string' && TXID_RE.test(txid);
}

/** "29.90" → 2990. Valor ausente ou inválido → null. */
export function toCents(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? Math.round(n * 100) : null;
}

/** Resumo da cobrança devolvida pela Efí (GET /v2/cob/:txid). */
export function summarizeCob(cob) {
  const pix = Array.isArray(cob?.pix) ? cob.pix : [];
  const paidCents = pix.reduce((sum, p) => sum + (toCents(p?.valor) ?? 0), 0);
  return {
    txid: cob?.txid ?? null,
    status: cob?.status ?? null,
    paid_at: pix[0]?.horario ?? null,
    paid_cents: pix.length > 0 ? paidCents : null,
    original_cents: toCents(cob?.valor?.original),
  };
}

/**
 * Confere na Efí cada txid do payload do webhook.
 * - verified: CONCLUIDA na Efí — o que pode ser repassado ao app;
 * - rejected: txid inválido ou cobrança não concluída (não adianta reenviar);
 * - errors:   a consulta à Efí falhou (vale pedir reenvio).
 */
export async function verifyWebhookPix(pixList, fetchCob) {
  const result = { verified: [], rejected: [], errors: [] };
  const list = Array.isArray(pixList) ? pixList : [];
  const seen = new Set();

  for (const item of list) {
    const txid = item?.txid;
    if (!isValidTxid(txid)) {
      result.rejected.push({ txid: typeof txid === 'string' ? txid.slice(0, 40) : null, reason: 'invalid_txid' });
      continue;
    }
    if (seen.has(txid)) continue;
    seen.add(txid);
    if (seen.size > MAX_TXIDS) {
      result.rejected.push({ txid, reason: 'too_many_txids' });
      continue;
    }

    let summary;
    try {
      summary = summarizeCob(await fetchCob(txid));
    } catch {
      result.errors.push(txid);
      continue;
    }
    if (summary.status !== 'CONCLUIDA') {
      result.rejected.push({ txid, reason: `not_concluded:${summary.status}` });
      continue;
    }
    result.verified.push({
      txid,
      horario: summary.paid_at,
      valor: summary.paid_cents === null ? null : (summary.paid_cents / 100).toFixed(2),
      efi_status: summary.status,
      paid_cents: summary.paid_cents,
      original_cents: summary.original_cents,
    });
  }
  return result;
}
