# Prompt for the next session — P3-04 onwards (control plane and agent)

> P3-03 is done on branch `redesign/p3-03-enrollment` (service layer, D-45…D-47). Next: P3-04 (bundle compiler). Carry-overs for P3-05: bind `renew` to the mTLS client CN; node deletion only via `EnrollmentService.revoke_node`; the `enroll` HTTP handler maps `EnrollmentError.status/code`.

Paste everything below the line into a fresh Claude Code session started in
`/home/lans/Cloud/Projects/public/kornode`. **Start on Opus in plan mode** (P3-03 is non-trivial: tokens, CSR, CRL,
a new ocserv user lifecycle), switch to Sonnet for the code once the plan is agreed.

---

Продолжаем редизайн kornode (hub+agents, один reconciler). Язык общения — русский, обращайся ко мне «Ivan».
Прочитай по порядку: `CLAUDE.md`, `AGENTS.md`, `docs/redesign/ROADMAP.md` (P3), раздел «Дальнейшие действия» в `docs/redesign/PLAN.ru.md`,
`docs/redesign/DECISIONS.md` (особенно D-29…D-44, S-01…S-04), `docs/spec/05`, `06`, `07`, `11`, `docs/spec/schemas/bundle.v1.schema.json`,
затем память Serena проекта `kornode`: `redesign/p2-hub-cutover`. Активируй проект Serena `kornode` до поиска по коду.

## Правила работы (важно, это про стоимость)
- **Меньше коммитов**: один коммит на задачу ROADMAP (P3-03, …), короткое тело. **Ничего не пушить** — пуш я скажу сам.
- Короткие отчёты. Не перечитывай файлы, которые уже читал в этой сессии.
- **Обратной совместимости нет (D-29).**
- Код пишет codex по узким промптам (`/tmp/codex_task.sh <prefix> <promptfile> [repo]`, stdin закрыт, по завершении `/tmp/<prefix>.done`,
  отчёт — последний `agent_message` в `/tmp/<prefix>.jsonl`; если обёртки нет — создай:
  `codex exec --json -s workspace-write -C <repo> --skip-git-repo-check "$(cat prompt)" < /dev/null`).
  Его дифф проверяешь сам; тесты, которые он «починил», сверяй по смыслу (не ослаблены ли).
  **Известная ловушка:** в песочнице codex зависает `fastapi TestClient` и полный `pytest`, он переписывает такие тесты на прямые вызовы функций
  (так было с `tests/test_fabric_settings_api.py` — я вернул оригинал). В промпте прямо запрещай менять тесты из-за зависания и проси гонять только таргетные тесты;
  полный `python3 -m pytest -q` гоняй сам (≈1 мин). При «usage limit» — пиши сам.
- Реальные сетевые тесты — только на VM, **никогда** не на этой (dev) машине (тут продакшн-контейнер `kornode:raven`):
  `lans@192.168.122.30` — только netlab (sudo без пароля, venv `~/kornode/.venv`, есть ocserv 1.3.0, openconnect, certtool, occtl, ocpasswd; **нет iptables и docker**):
  `rsync -az --delete --exclude .venv --exclude __pycache__ --exclude artifacts --exclude frontend/node_modules --exclude .git ./ lans@192.168.122.30:~/kornode/`
  затем `ssh lans@192.168.122.30 "cd ~/kornode && sudo .venv/bin/python -m pytest -m netlab -q"` (весь набор ≈3 мин; артефакты падений — `~/kornode/artifacts/netlab/`).
  Для e2e (P3-10) зарезервированы `192.168.122.173/.152/.237`.
- Перед ответом мне при остановке/вопросе — уведомление в Telegram (память `feedback_telegram_notify`; в прошлой сессии такой памяти не нашлось — если и сейчас нет, спроси, где она).
- **Скажи мне, когда переключиться** между Opus и Sonnet, не переключайся молча.
- Ревью перед коммитом задач, трогающих аутентификацию/ядро: агенты `security-reviewer` и `code-reviewer` (в этом проекте правило «тесты → секьюрити → коммит» для старых проектов формально выключено, но здесь ревью окупилось — делай).

## Состояние (на момент передачи, 2026-10-13)
Ветка `redesign/p3-02-ocserv-groups` (стек: архитектурные доки P3-04/P3-06 → P3-01 → спайки → P3-02), **не запушена**, `main` локально опережает `origin/main` на 44 коммита.
Дерево чистое. Последние коммиты: `445a414` (спайки S-01/S-02/S-04), `de1e305` (P3-02). `make check`: 772 passed, 33 skipped (netlab); `make parity` зелёный; netlab 33/33 на VM.

Сделано в P3 (подробности — `DECISIONS.md`, `docs/spec/05–07`, `ROADMAP.md`):
- Архитектура P3-04/P3-06 согласована: D-34…D-40 (подпись Ed25519, sealing секретов, монотонные версии, apply-with-confirm, `state.json` агента).
- **P3-01** — пакет `kornode.registry` (SQLite, WAL, миграции только вперёд, снапшоты `VACUUM INTO`), D-41.
- **Спайки:** S-01 прошёл *с оговоркой* (D-43), S-02 прошёл, **S-04 не прошёл** (`restrict-user-to-*` работает через `/usr/libexec/ocserv-fw` = iptables, без него молча не применяется) → D-44. S-03 — к P4.
- **P3-02** — при `fabric.enabled`:
  - ocserv: `auth = plain[...]` + `enable-auth = "certificate"`, `cert-user-oid`, `cert-group-oid = 2.5.4.11`; **клиенты только парольные** — валидатор `AppConfig` запрещает `auth.certificate/oidc/otp.ocserv_oath_auth` вместе с fabric (D-43).
  - connect-script (`OcservConfigRenderer.render_connect_script`) с guard'ом: пустая группа → `exit 1` (без него клиентский сертификат без OU входит без пароля), `agents` только для `agent-1..999`, `enroll` только для `enroll-*`.
  - `FabricGroupsService` (`services/fabric_groups.py`): файлы групп `clients`/`agents`/`enroll` и `config-per-user/agent-<id>` (`explicit-ipv4`) из реестра; `sync()` пишет атомарно и удаляет устаревшие; reload ocserv не нужен (файлы читаются при открытии сессии). **P3-03/P3-08 должны вызывать `sync()` после мутаций реестра.**
  - `fabric.enroll_pool` (по умолчанию `10.99.255.240/28`, вне `fabric.cidr`, D-42), в валидаторе пересечений и в панели Fabric settings.
  - Enroll ограничен статическими nft-правилами `kornode.net` (`NodeFacts.enroll`: в `input` только `tcp <адрес хаба>:8444`, в `forward` пул режется в обе стороны), порт пока константа `DEFAULT_CONTROL_PORT` в `config/reserved.py` — P3-05 заменит на `control.port`.
  - Зарезервированы имена `agent-<n>`, `enroll-*` и группы `agents`/`enroll` (`config/reserved.py`); `UserService.ensure_default_group` ставит парольным пользователям без группы `clients`.
- Netlab-хелперы для ocserv: `tests/netlab/ocserv_peers.py` (`Peer` — сырой openconnect-клиент с паролем или сертификатом, `issue_client_cert`, `read_env`), сценарии `tests/netlab/test_p3_groups.py` (на отрендеренном конфиге) и `test_spike_p3_groups.py`.

Решение о пуше (одним PR в `origin/main`, чтобы CI-netlab впервые прошёл на GitHub-раннере, либо напрямую в `main`) — за мной, не предлагай и не делай сам.

## Окружение
- На dev-машине нет `.venv`: `make check` работает через системный python; тесты — `python3 -m pytest` (не голый `pytest`: пакет `tests`),
  линтеры — `~/.local/bin/ruff`, `~/.local/bin/mypy`. `ruff format --check` на всём репо красный из-за старых файлов — форматируй только то, что меняешь.

## Порядок работы по P3
1. **P3-03 (следующая, Opus, режим плана):** регистрация — выпуск/отзыв токена, одноразовый ocserv-пользователь `enroll-<id>-<rnd>` в группе `enroll` (создаётся напрямую в ocpasswd с группой, истекает по `exp`), подпись CSR существующим CA через `certtool` (CN=`agent-<id>`, **OU=`agents`**, 90 дней), продление, отзыв через CRL. Спеку (`docs/spec/05`, раздел Enrollment) сверь с текущим кодом.
   Обязательно закрыть хвосты ревью безопасности P3-02:
   - **CRL:** в `ocserv.conf` нет `crl`; guard не сверяет сессию `agents` с реестром — отозванный/удалённый агент с живым сертификатом подключится и получит адрес из всего `fabric.cidr`. Добавить `crl`, ревокацию и netlab-сценарий «отозванный сертификат не подключается».
   - **Спуфинг source с enroll-сессии:** правила enroll матчатся по `ip saddr` пула без `iifname`; держатель enroll-пароля может подделать source вне пула и обойти drop (слепая атака). Сначала проверить netlab-тестом со спуфингом, затем закрыть (`iifname` сессии из connect-скрипта либо `rp_filter=1` на `vpns*`).
   - Адрес хаба `10.99.0.1` на dummy-интерфейсе в netlab ставится руками — это объект желаемого состояния для `kornode.net`, делается в P3-05 вместе с control API (занеси в spec 05, если ещё нет).
2. P3-04 (компилятор пакета, по согласованной архитектуре D-34…D-40) → P3-05 (control API, mTLS, long-poll, привязка к `10.99.0.1`) → **хвосты P2** (ниже) → P3-06/07 (агент и его CLI) → P3-08 (паритет: `korctl agent`, `/api/agents/*`, панель; `parity.yaml` обновляется в той же задаче) → P3-09 (backup/restore) → P3-10 (e2e на 4 VM).
3. Спайк S-03 проверяй в netlab до P4-01; S-05/S-06 уже закрыты фреймворком.
Хвосты P2 (пуш не блокируют, закрыть до P3-06 — агент работает на том же `kornode.net` без центра):
netlab-сценарий для D-32 «exit убран, пока соединение живо» (0 пакетов на uplink); окно второго писателя ядра на старте демона;
события netlink в обход backoff после прохода с ошибкой; grep-тест единственного писателя → проверка по импортам/AST.
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make check` → netlab; `parity.yaml` обновляется в той же задаче.

## Что нужно от меня для P3-10 (напомни заранее)
4 VM (`hub`, `agent-a`, `agent-b`, `ext`), self-hosted runner на `hub` и инвентарь в secrets/variables репозитория. Runner лучше поднять заранее.
Четвёртый адрес VM пока не определён (зарезервированы три: `192.168.122.173/.152/.237`); `192.168.122.30` — только netlab.
