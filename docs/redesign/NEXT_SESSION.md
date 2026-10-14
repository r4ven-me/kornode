# Prompt for the next session — P3-06 onwards (agent)

Paste everything below the line into a fresh Claude Code session started in
`/home/lans/Cloud/Projects/public/kornode`. **Start on Opus in plan mode** (P3-06 is non-trivial: agent run loop, apply-with-confirm, rollback),
switch to Sonnet for the code once the plan is agreed.

---

Продолжаем редизайн kornode (hub+agents, один reconciler). Язык общения — русский, обращайся ко мне «Ivan».
Прочитай по порядку: `CLAUDE.md`, `AGENTS.md`, `docs/redesign/ROADMAP.md` (P3), раздел «Дальнейшие действия» в `docs/redesign/PLAN.ru.md`,
`docs/redesign/DECISIONS.md` (особенно D-29…D-52, S-01…S-04), `docs/spec/05`, `06`, `07`, `11`, `docs/spec/schemas/bundle.v1.schema.json`,
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

## Состояние (на момент передачи, 2026-10-14)
Ветка `redesign/p3-05-control-api` (стек: доки P3-04/P3-06 → P3-01 → спайки → P3-02 → P3-03 → P3-04 → P3-05), последний коммит `1a7a7c1`, **не запушена**; `main` локально опережает `origin/main` на 44 коммита (ветки P3 ещё не влиты). Дерево чистое.
`make check`: 856 passed, 39 skipped (netlab), `make parity` зелёный, netlab 39/39 на VM. Следующая ветка — `redesign/p3-06-agent` от `redesign/p3-05-control-api`.
**Не сделано по P3-05:** `security-reviewer` и `code-reviewer` упали на лимите сессии — прогнать на дифе `30f611c..1a7a7c1` до пуша (правило «тесты → секьюрити → коммит» для этого проекта формально выключено, но на auth-задачах ревью окупалось).

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
- **P3-03** (D-45…D-47) — только сервисный слой, `services/enrollment.py` (`EnrollmentService`, ошибки `EnrollmentError(status, code, message)`):
  - `issue_token` (1 ч, в реестре `sha256(secret)`, пользователь `enroll-<node>-<id>` создаётся `UserService.create_enroll_user` с `ocpasswd -g enroll`; предыдущий токен узла отзывается), `revoke_token`, `purge_expired`, `maintain` (чистка токенов, `sync()` групп, обновление CRL старше 10 суток + reload ocserv).
  - `enroll`: порядок ошибок 403 (неизвестный id/неверный секрет, неразличимы, аудит) → 410 → 409 → 400; подписывается **только публичный ключ** CSR (`certtool --load-pubkey`, CN=`agent-<id>`, OU=`agents`, 90 дней, ECDSA P-256), токен занимается атомарно вместе с подписью, состояние узла перечитывается внутри транзакции; пост-коммитные шаги (удаление enroll-пользователя, `sync()`) best-effort, сбой лечит `maintain()`. Поле `bundle` в ответе — `None`-заглушка до P3-04.
  - `renew` (после 2/3 срока, старый сертификат не отзывается), `renewal_warning` (за 14 дней), `revoke_node` (состояние `revoked` + CRL + reload + `occtl disconnect` + `sync()`, все шаги выполняются, ошибки собираются в `EnrollmentError 500`). Сертификаты хранятся в `certs/agents/agent-<id>-<serial>.crt`.
  - `ocserv.conf`: `crl = certs/crl.pem` при `fabric.enabled` (`ConfigService` создаёт пустой CRL, если есть CA); guard connect-script требует `config-per-user/agent-<id>`.
  - **Строгий RPF для сессий ocserv:** `iifname "<server.device>*" meta nfproto ipv4 fib saddr . iif oif missing drop` в начале `prerouting` (`EnrollGuard.session_iface`) — закрывает подделку source с enroll-сессии (подтверждено netlab, тест красный без правила).
  - `korctl registry maintain` в supervisor-цикле рядом со снапшотом (строка в `parity.yaml` с exempt); `cryptography` стала runtime-зависимостью.
  - Token-документ расширен полем `id` (spec 05 обновлена).
  - Netlab: `tests/netlab/test_p3_enrollment.py` — enroll по CSR → вход в `agents`; отозванный сертификат не подключается и живая сессия рвётся (ocserv подхватывает CRL по SIGHUP); удалённый из реестра агент отклоняется; спуфинг source. Hub-вызовы идут скриптом в namespace хаба (`_hub_call`), пока нет Control API.
- **P3-05** (D-49…D-52) — `kornode.control`, процесс `python -m kornode.control` (supervisor `control-api`, при `control.enabled`), `10.99.0.1:<control.port>`:
  - mTLS на одном порту: `CERT_OPTIONAL` + `PeerCertProtocol` (подкласс `H11Protocol`, кладёт проверенный DER в состояние соединения) + `MutualTLSMiddleware` (сертификат обязателен везде, кроме `POST /agent/v1/enroll`; CN `agent-<id>` и OU `agents`, CRL с кэшем по mtime — нет/устарел → 503, `nodes.state`). Серверный сертификат `certs/control.crt` (IP SAN = адрес хаба).
  - Эндпоинты `/agent/v1`: `ping`, `bundle`, `poll` (long-poll, перепроверка реестра раз в 500 мс; `since` выше последней версии → `compile_node(force=True)` и рост `high_water_version`), `report` (≤256 КиБ, схема, `node_id` из сертификата), `commands` + `commands/<id>/result`, `renew` (node_id из CN), `enroll` (5/мин на адрес). Ошибки `{"error", "message"}`.
  - Секция `control.*` (порт, long-poll, интервалы, `cert_lifetime_days`, `enroll_token_ttl_minutes`, `bundle_history`, `min_agent_version`, `signing_key`) заменила константы; сохранение YAML хаба (`ConfigService.write_rendered_files`) пересобирает пакеты; `compile_all` на старте control API.
  - `kornode.net`: примитив `Address` (только добавление), `NodeFacts.service_address` → `10.99.0.1/32` на `lo`; `Kernel.read(..., address_devs)`.
  - Реестр: `add_report` (последние 500), очередь команд (`enqueue/claim/finish`, at-most-once, истечение 10 мин), `raise_high_water`. Поверхности CLI/API/панель для команд — P3-08.
  - **D-51:** `enroll(end_session=False)`; VPN-сессию enroll закрывает control API через 5 с после ответа (иначе `occtl disconnect` рвал туннель с ответом — сертификат терялся). Потерянный ответ лечится отзывом и пересозданием узла.
  - Netlab (`test_p3_enrollment.py`, `test_p3_groups.py`): control API запускается в namespace хаба, enroll/poll/ping/403 `revoked`/401 — реальный HTTPS; `_hub_call` остался только для `create`, `token`, `revoke`, `delete`.
- Netlab-хелперы для ocserv: `tests/netlab/ocserv_peers.py` (`Peer` — сырой openconnect-клиент с паролем или сертификатом, `issue_client_cert`, `read_env`), сценарии `tests/netlab/test_p3_groups.py` (на отрендеренном конфиге) и `test_spike_p3_groups.py`.

Решение о пуше (одним PR в `origin/main`, чтобы CI-netlab впервые прошёл на GitHub-раннере, либо напрямую в `main`) — за мной, не предлагай и не делай сам.

## Окружение
- На dev-машине нет `.venv`: `make check` работает через системный python; тесты — `python3 -m pytest` (не голый `pytest`: пакет `tests`),
  линтеры — `~/.local/bin/ruff`, `~/.local/bin/mypy`. `ruff format --check` на всём репо красный из-за старых файлов — форматируй только то, что меняешь.

## Порядок работы по P3
1. ~~P3-03~~, ~~P3-04~~, ~~P3-05~~ — готовы. Переносы дальше:
   - P3-08: `korctl agent ...`, `/api/agents/*`, панель; после мутаций реестра вызывать `FabricGroupsService.sync()` и `BundleService.compile_*`; `control.status` / `control.rotate_key` (spec 08); удаление узла только через `EnrollmentService.revoke_node`.
   - Хвост (низкий приоритет): CRL ocserv перечитывается по SIGHUP — проверено в netlab.
2. **P3-06 (Opus, режим плана)** — пакет `kornode_agent` + образ `kornode-agent`: enroll, run loop (`GET /agent/v1/poll`), кэш 3 версий, verify (`kornode.bundle.validator`), apply-with-confirm и откат, загрузка из кэша, отчёты (`POST /report`, 30 с), команды. Зависит только от `kornode.net` и `kornode.bundle` (AST-тест импортов). Затем P3-07 (CLI `kornode-agent`), P3-08, P3-09, P3-10.
3. Спайк S-03 проверяй в netlab до P4-01; S-05/S-06 уже закрыты фреймворком.
Хвосты P2 (пуш не блокируют, закрыть до P3-06 — агент работает на том же `kornode.net` без центра):
netlab-сценарий для D-32 «exit убран, пока соединение живо» (0 пакетов на uplink); окно второго писателя ядра на старте демона;
события netlink в обход backoff после прохода с ошибкой; grep-тест единственного писателя → проверка по импортам/AST.
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make check` → netlab; `parity.yaml` обновляется в той же задаче.

## Что нужно от меня для P3-10 (напомни заранее)
4 VM (`hub`, `agent-a`, `agent-b`, `ext`), self-hosted runner на `hub` и инвентарь в secrets/variables репозитория. Runner лучше поднять заранее.
Четвёртый адрес VM пока не определён (зарезервированы три: `192.168.122.173/.152/.237`); `192.168.122.30` — только netlab.
