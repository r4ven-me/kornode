# Prompt for the next session — P3 (control plane and agent)

Paste everything below the line into a fresh Claude Code session started in
`/home/lans/Cloud/Projects/public/kornode`. **Start on Opus in plan mode** (architecture of P3-04/P3-06),
switch to Sonnet for the code once the plan is agreed.

---

Продолжаем редизайн kornode (hub+agents, один reconciler). Язык общения — русский, обращайся ко мне «Ivan».
Прочитай по порядку: `CLAUDE.md`, `AGENTS.md`, `docs/redesign/ROADMAP.md` (P3),
`docs/redesign/DECISIONS.md` (особенно D-29…D-31, S-01…S-04), `docs/spec/04`, `05`, `06`, `11`, `docs/spec/schemas/bundle.v1.schema.json`,
затем память Serena проекта `kornode`: `redesign/p2-hub-cutover`. Активируй проект Serena `kornode` до поиска по коду.

## Правила работы (важно, это про стоимость)
- **Меньше коммитов**: один коммит на задачу ROADMAP (P3-01, …), короткое тело. **Ничего не пушить** — пуш я скажу сам.
- Короткие отчёты. Не перечитывай файлы, которые уже читал в этой сессии.
- **Обратной совместимости нет (D-29).**
- Код пишет codex по узким промптам (`/tmp/codex_task.sh <prefix> <promptfile> [repo]`, stdin закрыт, по завершении `/tmp/<prefix>.done`;
  если обёртки нет — создай: `codex exec --json -s workspace-write -C <repo> --skip-git-repo-check "$(cat prompt)" < /dev/null`).
  Его дифф проверяешь сам; тесты, которые он «починил», сверяй по смыслу (не ослаблены ли). При «usage limit» — пиши сам.
- Реальные сетевые тесты — только на VM, **никогда** не на этой (dev) машине (тут продакшн-контейнер `kornode:raven`):
  `lans@192.168.122.30` — только netlab (sudo без пароля, venv `~/kornode/.venv`):
  `rsync -az --delete --exclude .venv --exclude __pycache__ --exclude artifacts --exclude frontend/node_modules --exclude .git ./ lans@192.168.122.30:~/kornode/`
  затем `ssh lans@192.168.122.30 "cd ~/kornode && sudo make netlab"`. Для e2e (P3-10) зарезервированы `192.168.122.173/.152/.237`.
- Перед ответом мне при остановке/вопросе — уведомление в Telegram (память `feedback_telegram_notify`).
- **Скажи мне, когда переключиться** между Opus и Sonnet, не переключайся молча.

## Состояние (на момент передачи, 2026-10-13)
Локальный `main` (опережает `origin/main` на ~40 коммитов, **не запушен**) содержит P0, P1 и весь P2: хаб работает на одном reconciler.
- `net/kernel.py` — единственный писатель ядра (nft, ip rule/route, sysctl); `tests/test_kernel_single_writer.py` это проверяет.
- `NetService`: `apply()` (синхронный проход по `reconciler.sock`, иначе in-process; таймаут/мусор = `NetApplyError`, второго писателя нет),
  `converge()` (то же, но бросает при `last_error`), `wake()` (асинхронный толчок для хуков/резолвера). D-30.
- Активный профиль в рантайме (`generated_dir/active-upstream`) — вход reconciler (D-31). Carrier-адреса — `upstream-carrier/<p>.addrs`, резолв — `resolved/<set>.txt`.
- `connect()`: carrier → converge (kill-switch) → dial → converge. Netlab 24/24 на VM, 700+ юнит-тестов.
- Метка/таблица выхода зависят от его индекса в политике (при `client_policy: off` upstream = таблица 12002 / `0x0c000200`); читай из `korctl net plan --json`.
Решение о пуше (одним PR `redesign/p2` → `origin/main`, чтобы CI-netlab впервые прошёл на GitHub-раннере, либо напрямую в `main`) — за мной, не предлагай и не делай сам.

## Окружение
- На dev-машине нет `.venv`: `make check` работает через системный python; тесты — `python3 -m pytest` (не голый `pytest`: пакет `tests`),
  линтеры — `~/.local/bin/ruff`, `~/.local/bin/mypy`.

## Порядок работы по P3
1. **Opus, режим плана** — архитектура P3-04 + P3-06: формат бандла по `bundle.v1.schema.json`, подпись Ed25519, sealing секретов (D-16),
   монотонные версии, apply-with-confirm и rollback агента, загрузка из кэша. Результат: обновлённые `docs/spec/05`, `06` и записи в `DECISIONS.md`. Код — после моего согласования.
2. Без архитектурного блока (можно параллельно, на Sonnet): **P3-01** (registry на SQLite, WAL, `VACUUM INTO`), **P3-02** (группы ocserv `clients`/`agents`/`enroll`).
3. Далее: P3-03 (enroll, CSR, CRL) → P3-05 (control API, mTLS, long-poll) → P3-06/07 (агент и его CLI) → P3-08 (паритетные поверхности: `korctl agent`, `/api/agents/*`, панель) → P3-09 (backup/restore) → P3-10 (e2e на 4 VM).
4. Spike S-01…S-04 проверяй в netlab до того, как строить на них код.
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make check` → netlab; `parity.yaml` обновляется в той же задаче.

## Что нужно от меня для P3-10 (напомни заранее)
4 VM (`hub`, `agent-a`, `agent-b`, `ext`), self-hosted runner на `hub` и инвентарь в secrets/variables репозитория. Runner лучше поднять заранее.
