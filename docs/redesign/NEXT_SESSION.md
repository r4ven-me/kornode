# Prompt for the next session — P3-05 onwards (control plane and agent)

Paste everything below the line into a fresh Claude Code session started in
`/home/lans/Cloud/Projects/public/kornode`. **Start on Opus in plan mode** (P3-05 is non-trivial: mTLS control API, long-poll, supervisor program),
switch to Sonnet for the code once the plan is agreed.

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
Ветка `redesign/p3-03-enrollment` (стек: архитектурные доки P3-04/P3-06 → P3-01 → спайки → P3-02 → P3-03), **не запушена**, `main` локально опережает `origin/main` на 44 коммита (ветки P3 ещё не влиты в `main`).
Дерево чистое. Последние коммиты: `de1e305` (P3-02), `a9d2919` (P3-03). `make check`: 793 passed, 37 skipped (netlab); `make parity` зелёный; netlab 37/37 на VM.
**P3-04 готова** (ветка `redesign/p3-04-bundle-compiler`, D-48, `make check` 828 passed / 37 skipped): пакет `kornode.bundle`, `services/bundle.py` (`BundleService.compile_node/compile_all` внутри транзакции вызывающего), первый пакет и `signing_keys` в ответе `enroll`; отзыв пересобирает пакеты остальных per-node. Валидатор требует `expected_node_id`. Мастер-ключ — `data_dir/control/master.key`. Следующая ветка — `redesign/p3-05-control-api` от `redesign/p3-04-bundle-compiler`. P3-05 должна: заменить константы `BUNDLE_HISTORY`/`MIN_AGENT_VERSION`/порт на `control.*`, вызывать `compile_node` при `since` > последней версии (recovery, D-37), вызывать `compile_all` при сохранении YAML хаба и на старте.

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
- Netlab-хелперы для ocserv: `tests/netlab/ocserv_peers.py` (`Peer` — сырой openconnect-клиент с паролем или сертификатом, `issue_client_cert`, `read_env`), сценарии `tests/netlab/test_p3_groups.py` (на отрендеренном конфиге) и `test_spike_p3_groups.py`.

Решение о пуше (одним PR в `origin/main`, чтобы CI-netlab впервые прошёл на GitHub-раннере, либо напрямую в `main`) — за мной, не предлагай и не делай сам.

## Окружение
- На dev-машине нет `.venv`: `make check` работает через системный python; тесты — `python3 -m pytest` (не голый `pytest`: пакет `tests`),
  линтеры — `~/.local/bin/ruff`, `~/.local/bin/mypy`. `ruff format --check` на всём репо красный из-за старых файлов — форматируй только то, что меняешь.

## Порядок работы по P3
1. ~~P3-03~~ — **готова** (см. выше). Переносы в P3-05/P3-08:
   - `renew` не аутентифицирует вызывающего: в P3-05 `node_id` брать из CN клиентского сертификата mTLS, не из тела запроса.
   - Удаление узла только через `EnrollmentService.revoke_node` (ключи SQLite переиспользуются: неотозванный `agent-N` подошёл бы новому узлу с тем же id); `Registry.delete_node` из API не вызывать напрямую.
   - HTTP-обработчики `/agent/v1/enroll` и `/agent/v1/renew` — тонкие обёртки над сервисом; `EnrollmentError.status/code` → ответ `{"error": code, "message": ...}` по spec 05; rate limit 5/мин на адрес — в обвязке.
   - Адрес хаба `10.99.0.1` на dummy-интерфейсе в netlab всё ещё ставится руками — объект желаемого состояния `kornode.net`, P3-05.
   - После мутаций реестра (создание/активация/отзыв узла) вызывать `FabricGroupsService.sync()`; `EnrollmentService` уже делает это сам.
   - `cert_lifetime_days` пока константа `CERT_LIFETIME_DAYS = 90`, порт enroll — `DEFAULT_CONTROL_PORT`; P3-05 вводит секцию `control.*` и заменяет обе.
   - Хвост (низкий приоритет): CRL ocserv перечитывается по SIGHUP — проверено в netlab; при смене `crl` в конфиге рестарт не нужен.
2. ~~P3-04~~ — готова. Дальше: **P3-05 (Opus, режим плана)** — компилятор пакета, по согласованной архитектуре D-34…D-40 (`bundle/` без зависимостей от остального `kornode`, AST-тест импортов; компиляция в `Registry.transaction()`; поле `bundle` в ответе `enroll` заменяет заглушку) → P3-05 (control API, mTLS, long-poll, привязка к `10.99.0.1`) → **хвосты P2** (ниже) → P3-06/07 (агент и его CLI) → P3-08 (паритет: `korctl agent`, `/api/agents/*`, панель; `parity.yaml` обновляется в той же задаче) → P3-09 (backup/restore) → P3-10 (e2e на 4 VM).
3. Спайк S-03 проверяй в netlab до P4-01; S-05/S-06 уже закрыты фреймворком.
Хвосты P2 (пуш не блокируют, закрыть до P3-06 — агент работает на том же `kornode.net` без центра):
netlab-сценарий для D-32 «exit убран, пока соединение живо» (0 пакетов на uplink); окно второго писателя ядра на старте демона;
события netlink в обход backoff после прохода с ошибкой; grep-тест единственного писателя → проверка по импортам/AST.
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make check` → netlab; `parity.yaml` обновляется в той же задаче.

## Что нужно от меня для P3-10 (напомни заранее)
4 VM (`hub`, `agent-a`, `agent-b`, `ext`), self-hosted runner на `hub` и инвентарь в secrets/variables репозитория. Runner лучше поднять заранее.
Четвёртый адрес VM пока не определён (зарезервированы три: `192.168.122.173/.152/.237`); `192.168.122.30` — только netlab.
