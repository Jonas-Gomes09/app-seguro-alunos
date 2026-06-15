# ⚠️ App Seguro — Aula 36 (Ataques + Proteção)

Este app tem **11 VULNERABILIDADES PROPOSITAIS**. Sua missão em 2 partes:

## Parte A — Caçar e corrigir vulnerabilidades
1. Secret fraco ("123") → trocar por string longa: OK
2. httpOnly: false → trocar por true: OK
3. Senha comparada em texto puro → instalar bcrypt, usar compare: OK
4. Mensagem revela email → "Email ou senha incorretos": OK
5. Registro sem validação → validar campos: OK
6. Senha texto puro → bcrypt.hash: OK
7. Comentário sem validação → validar texto: OK
8. IDOR: editar sem userId → verificar dono: OK
9. IDOR: remover sem userId → verificar dono: OK
10. API retorna senhas → filtrar: OK
11. Admin sem role check → verificar
12. (BÔNUS) View usa <%- %> → trocar por <%= %>

## Parte B — Adicionar ferramentas de proteção
As dependências já estão no package.json!

```bash
npm install
npm run dev
```

Criar:
- src/middlewares/validators.ts (express-validator)
- src/middlewares/rateLimiter.ts (express-rate-limit)
- Atualizar app.ts: helmet() + cors() + limiters + validators nas rotas

## Testar
- XSS: <script>alert("XSS")</script> como comentário
- IDOR: remover comentário de outro usuário
- /api/usuarios: senhas visíveis?
- /admin: user normal acessa?
- Thunder Client: POST com campos vazios
- Login 6x errado: rate limit
- F12 → Network → Response Headers (Helmet)
