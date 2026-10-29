# VLESS Vault — Серверлесс-менеджер подписок (Happ / Invy)

Бесплатная система управления персональными VLESS-ключами через связку:
1. **GitHub Pages (Web UI)** — мобильное PWA-приложение для телефона (`index.html`).
2. **GitHub Gist** — база данных ключей (`all.txt`, `favourites.txt`, `config.json`, `db.json`).
3. **GitHub Actions** — автоматический TCP-пинг серверов каждые 6 часов и отсев молчащих узлов (`check_keys.py`).

## Быстрый старт

### 1. Настройка секретов репозитория
Перейдите в **Settings → Secrets and variables → Actions** и добавьте два секрета:
- `GIST_TOKEN` — ваш GitHub Personal Access Token с правами `gist`.
- `GIST_ID` — ``.

### 2. Включение GitHub Pages
Перейдите в **Settings → Pages**:
- **Source:** Deploy from a branch
- **Branch:** `main` / `root`
- Нажмите **Save**.

Откройте полученную ссылку на телефоне и сохраните на домашний экран как PWA.
