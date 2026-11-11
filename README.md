# RZEnergy CRM

Site (public/index.html) + API (api/[...path].js) + base de dados Postgres (Neon).

## Colocar online na Vercel
1. Crie um repositório no GitHub e envie esta pasta (ou use `npx vercel` na pasta).
2. Em vercel.com: **Add New → Project** → escolha o repositório (Framework Preset: **Other**).
3. No projeto: **Storage → Create Database → Neon (Postgres)** → ligar ao projeto. Isto cria a variável `DATABASE_URL`.
4. **Settings → Environment Variables**: crie `JWT_SECRET` com um texto aleatório longo (ex.: resultado de `openssl rand -hex 32`).
5. **Deployments → Redeploy**.
6. Abra o endereço do projeto: aparece "Criar conta de Administrador". Depois crie os comerciais na aba Utilizadores.
