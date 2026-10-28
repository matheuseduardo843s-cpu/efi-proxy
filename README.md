# Efí PIX Proxy

Proxy Node.js que faz ponte entre seu app Lovable e a API Efí Bank.
Necessário porque o runtime Cloudflare Workers não suporta mTLS com certificado cliente.

## Deploy no Render.com (grátis, 5 min)

### 1. Criar repositório GitHub
```bash
cd efi-proxy
git init
git add .
git commit -m "efi proxy"
# Crie um repo no GitHub e:
git remote add origin https://github.com/SEU_USUARIO/efi-proxy.git
git push -u origin main
```

### 2. Deploy no Render
1. Acesse https://render.com e faça login com GitHub
2. **New +** → **Web Service** → conecte seu repo `efi-proxy`
3. Configurações:
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
   - **Instance Type**: Free
4. **Environment Variables** (adicione uma a uma):
   - `EFI_CLIENT_ID` → seu Client ID da Efí
   - `EFI_CLIENT_SECRET` → seu Client Secret da Efí
   - `EFI_CERTIFICATE_BASE64` → certificado .p12 em base64 (mesmo que você já colocou no Lovable)
   - `EFI_SANDBOX` → `true` para testes ou `false` para produção
   - `EFI_PIX_KEY` → sua chave PIX cadastrada na Efí (CPF/CNPJ/email/aleatória)
   - `PROXY_SECRET` → uma senha forte aleatória (ex: `openssl rand -hex 32`). Esta mesma senha deve ser salva como `EFI_PROXY_SECRET` no Lovable.
   - `WEBHOOK_FORWARD_URL` → `https://controle-finca.lovable.app/api/public/hooks/efi-webhook`

5. Clique **Create Web Service**. Aguarde o deploy (~2 min).
6. Copie a URL gerada (ex: `https://efi-proxy-xxxx.onrender.com`) e cole em `EFI_PROXY_URL` nos secrets do Lovable.

### 3. Configurar webhook na Efí
No painel Efí → **API** → **Webhooks**, configure:
- URL: `https://SEU-PROXY.onrender.com/webhook/pix`
- O Render encerra o TLS antes do proxy, então o mTLS do webhook **não** chega até aqui.
  Por isso o proxy não confia no corpo recebido: cada `txid` é consultado na Efí
  (`GET /v2/cob/:txid`) e só o que está `CONCLUIDA` é repassado (ver `webhook-verify.js`).

## Endpoints do proxy

- `POST /pix/create` — cria uma cobrança PIX dinâmica
- `GET /pix/status/:txid` — consulta status de uma cobrança (inclui `paid_cents` e `original_cents`)
- `POST /webhook/pix` — recebe notificações da Efí, confere cada txid na Efí e encaminha ao app só os PIX concluídos

`/pix/create` e `/pix/status` exigem header `X-Proxy-Secret: <PROXY_SECRET>`. O `/webhook/pix` é público
(a Efí não envia o segredo) e por isso valida tudo na própria Efí antes de repassar.
