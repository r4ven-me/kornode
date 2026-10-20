# Передача Claude — накопительная

Обновлено: **2026-10-17**. Основной агент — Claude: финальное ревью и приёмка за ним.
Этот файл **дополнять после каждой задачи**, не заменять предыдущие передачи.

## Текущее рабочее дерево

- Ветка **`redesign/p3-08-agent-management`**, от P3-07/P3-06.
- **P3-07, P3-08, P3-09 и P3-10 не закоммичены**, не влиты и не запушены. Не reset/stash/drop;
  не коммитить/merge/push без отдельного разрешения владельца.
- Просмотреть и tracked diff, и **все untracked файлы**: `git diff --stat` их не показывает.
- План P3-08 согласован владельцем: общий service layer + полный CLI/API/GUI parity,
  включая control status/signing rotation; честная граница P4, без расширения runtime.
- Реализовывал один вспомогательный агент, без субагентов. Текущая просьба владельца
  о единственном основном Claude важнее исторического workflow делегирования в NEXT_SESSION.
- **P3-07/P3-08/P3-09/P3-10 реализованы, но не объявлены окончательно done**:
  нужны Claude review, privileged netlab и реальное four-VM evidence. По прямому
  поручению владельца P3-09/P3-10 выполнены **до ревью** pending P3-07/P3-08;
  их приёмка этим не подменена. Следующий шаг — ревью/приёмочные проверки,
  не повторная реализация P3-10. Все предыдущие передачи и результаты сохранены.
- P3-10: [P3-10-REVIEW.md](P3-10-REVIEW.md), D-58,
  [VM runbook](../runbooks/vm-e2e.md). **Ни один VM/Docker/privileged запуск здесь
  не выполнялся**. 49 local safety + 4 parity passed; полный check всё ещё red
  из-за двух прежних clock failures. Подробности и актуальные цифры — внизу.

## P3-07 — CLI агента (предыдущая передача сохранена)

Подробно: [P3-07-REVIEW.md](P3-07-REVIEW.md), решение D-55, spec 06.

- `status`, `explain`, `doctor`, `bundle show|history|rollback`, `diag`, `reconnect`,
  JSON и exit codes; cache/offline inspection без хаба/процесса.
- Owner-only Unix RPC, процессный flock до boot; общие локальные/удалённые команды,
  сериализация с apply и ожидание workers при cancellation; без второго reconciler.
- Read-only doctor и общий safe diag, redacted проверенные bundles, atomic no-clobber архивы.
- Исторический итог P3-07: **53 новых теста passed**; полный check: ruff/mypy passed,
  **948 passed / 40 skipped / 2 известных enrollment failures**. Netlab: 1 skipped,
  не подтверждённый runtime. Эти цифры не заменяются результатами P3-08 ниже.
- Дополнение P3-08: Redactor перенесён в разрешённый общий пакет
  `backend/kornode/bundle/redaction.py`; agent inspection использует его без импорта
  hub services. В P3-07-REVIEW оставлен исторический scope и добавлен актуальный указатель.

## P3-08 — управление агентами на хабе (новая передача)

Подробно: [P3-08-REVIEW.md](P3-08-REVIEW.md), D-56, specs 05/08, `parity.yaml`.

- `AgentService`/`ControlManagement`, 37 CLI leaf-команд, 32 admin endpoints,
  раздел Agents; **39 новых parity capabilities без exemptions**.
- CRUD/token/revoke/delete, ID allocation/30-day quarantine/force reuse; shared
  validation + transactional compile; ocserv group sync после commit и общий lock
  от snapshot до записи файлов, защита от воскресшего revoked guard.
- Policies/networks/sources/upstreams/access-user registry; reports, redacted
  history/diff; типизированные remote commands/results и явная загрузка diag.
- Staged Ed25519 rotation: семь дней announcement старой подписью, затем promotion
  при compile/poll; SQLite хранит пути, старые private keys сохраняются.
- Секреты write-only/encrypted, sanitized ошибки/no-store, токен только explicit
  create/reissue, ephemeral masked dialog. Schema 2, без новых зависимостей/AppConfig.
- Revoke перед delete; ошибка disconnect игнорируется только при доказанном
  отсутствии сессии (`occtl --json show user` → валидный `[]`); неисправный occtl
  блокирует удаление. Reload через occtl, не требует supervisor.
- P4 **не считается работающим**: access users/roles/exported prefixes — подготовка;
  p12/pushed routes/domain/URL resolution/exit:N отклоняются до runtime-поддержки.

### Итоговая проверка после P3-08

- `make check PYTHON=python3`: ruff **passed**, mypy strict **passed (130 files)**;
  pytest **983 passed, 41 skipped, 2 failed**, 114.11 s. Это **не зелёный make check**.
- Падают известные тесты `tests/test_enrollment.py`:
  `test_renew_only_after_two_thirds_and_keeps_old_cert` и
  `test_revoke_node_crl_reload_disconnect_and_sync`: fixed test clock против
  реальной даты certtool. До renew/revoke assertions второй тест не доходит.
  Не ослаблялись и не исправлялись в этой задаче.
- Новые P3-08 backend-тесты: **35 passed** (management/surfaces/sync/revocation/rotation).
- `make parity PYTHON=python3`: **4 passed**.
- Frontend vitest: **23 passed**, включая 4 Agents component tests; production build passed.
- Chromium: **4 passed**, 1440×900 / 390×844, обе темы; overflow, targets 40/44px,
  primary contrast ≥4.5, focus, отсутствие alert/page errors, реальные скриншоты.
  Это UI **с mocked admin API**, не fabric e2e на VM.
- Новый `tests/netlab/test_p3_management.py`: **1 skipped** локально (нужен root/ocserv).
  Добавлен сценарий CLI с реальным ocpasswd/ocserv при `web.enabled:false`.
- Docker image/размер ≤150 MB, CI-netlab и 4-VM e2e **не проверены**.

## Порядок ревью и приёмки после P3-08 (исторический; дополнение P3-09 ниже)

1. Прочитать оба REVIEW и D-55/D-56, просмотреть всё рабочее дерево, включая новые файлы.
2. P3-07: lifecycle locks/cancellation, socket permissions, rollback/high-water,
   redaction/diag и границы doctor/explain. P3-08: transactions/locks, revoke→delete,
   offline disconnect proof, encrypted transport/upstreams, auth/CSRF/no-store,
   schema migration/quarantine, ротация нескольких ключей/пропущенное announcement.
3. На подготовленной **netlab VM**, не на production/dev-хосте: сначала
   `tests/netlab/test_p3_agent.py` и `tests/netlab/test_p3_management.py`, затем весь
   netlab, включая enrollment/groups. Новый management smoke не заменяет остальные.
4. Отдельно устранить wall-clock зависимость двух старых enrollment-тестов и
   получить зелёный полный check **до push**. Не менять production renewal окно ради тестов.
5. Собрать `Dockerfile.agent`, записать размер. После приёмки планировать P3-09.

## Накопленные хвосты и зависимости (не потерять)

- P3-09 backup: DB + hub CA/master key + **все referenced rotation signing-key files**,
  включая кастомные пути вне data_dir; один исходный `control.signing_key` недостаточен.
- P2 до P3-10: D-32 netlab, окно второго kernel writer на старте reconciler,
  netlink bypass error backoff, grep single-writer → AST. Не правились в P3-07/08.
- D-54: domain resolution/pushed routes/p12 остаются не реализованы; doctor добавлен P3-07.
- P0: 50 MB upload через вложенный tunnel при MTU 1500/1400 всё ещё не подтверждён.
- P1: GitHub-hosted CI-netlab ещё не запускался. Решение о push/PR только владельца.
- P3-10: 4 VM (`hub`, `agent-a`, `agent-b`, `ext`), четвёртый адрес, self-hosted runner
  на hub, inventory в repo secrets/variables должен подготовить владелец.
- `NEXT_SESSION.md` содержит исторический P3-06 prompt; актуальный старт — этот файл.

## P3-09 — encrypted hub backup / staged restore (дополнение, 2026-10-16)

Подробно: [P3-09-REVIEW.md](P3-09-REVIEW.md), implementation choice D-57,
[runbook](../runbooks/hub-recovery.md). **Не принято окончательно.**

- Общий `BackupService` для CLI `hub backup|restore`, двух admin endpoints и
  Config → Backup / Restore; **2 новые parity capabilities без exemptions**.
- Argon2id 64 MiB/t3/p4 + ChaCha20-Poly1305, фиксированный authenticated v1 header,
  random salt/nonce, strict bounded records без tar/compression. `cryptography >=44`.
- DB snapshot с WAL consistency + effective config + CA/TLS/master/secret/user/group
  files + **все DB-referenced rotation keys**, в том числе custom вне data_dir.
  Authority/подписи/secret ciphertext сохраняются, typed config и rotation DB paths remap.
- Atomic private no-clobber encrypted output; source-change detection; integrity,
  schema/key coverage/path/mode checks; missing keys не генерируются заново.
- **Restore только staged**, в новый private root: existing/live файлы и сеть не
  заменяются, config публикуется последним, failed staging чистит только свой root.
  Managed connect hook регенерируется с новыми путями. API не принимает target path.
- CLI hidden prompts/private passphrase file, без secret argv; API auth/CSRF/no-store,
  streaming encrypted download/bounded ciphertext upload. UI clears passwords после
  каждого запроса, validation → confirmation → stage, global dry-run блокирует stage.

### Итоговая проверка после P3-09 (не заменяет исторические цифры выше)

- Новые backend tests: **37 passed**; parity: **4 passed** (совместно **41 passed**).
- Последний `make check` с локальной ignored `.venv` (Python 3.13.5,
  cryptography 45.0.7): ruff **passed**, mypy strict **passed, 135 files**;
  pytest **1020 passed, 42 skipped, 2 failed**, 133.53 s. **Не зелёный check.**
- Всё те же clock-dependent enrollment failures, без изменений/ослабления их или
  production renewal logic. До их исправления полный зелёный check не заявляется.
- Frontend **29 passed**, build passed. Новые Chromium backup tests **4 passed**;
  вместе с P3-08 Agents regression — **8 passed**. Desktop/mobile, обе темы,
  download/validation/staging, CSRF, clearing secrets, overflow/targets,
    primary + destructive contrast ≥4.5/focus; desktop/light и mobile/dark screenshots просмотрены.
  Это mocked admin API UI, **не real VPN/VM acceptance**.
- `tests/netlab/test_p3_backup.py`: **1 skipped локально**; real enroll → rotation →
  backup → stop fixture listeners → guarded fixture wipe → staged restore → explicit
  activation → reconnect исходным agent cert/pin → mTLS/high-water poll recovery.
- `git diff --check` passed. Docker/CI/four-VM P3-10 не выполнялись. Коммитов/веток/
  merge/push не создавалось. Привилегированная сеть dev/production не менялась.

### Что Claude должен отдельно принять/проверить

1. Прочитать все три REVIEW и рассмотреть **всё дерево с untracked**, не только P3-09.
2. Принять/доработать D-57: staged restore **не live switch**; offline activation и
   fencing старого hub обязательны. Private root 0700 требует explicit traversal 0711
   при activation для dropped-privilege ocserv workers; не раскрывать private keys.
3. DB/management locking + stat checks **не универсальная filesystem transaction**.
   Legacy config/user/OTP/CA/external writers требуют maintenance-window quiescence.
   Обязательное ревью consistency, symlink/target boundaries и failed-write cleanup.
4. Check missing/future/corrupt DB, referenced custom keys, повторные ротации,
   remapped managed hook/user config permissions, key-pair checks, scratch/limit/RAM
   и secret header logging policies. Старые backups теряют последующие revocations.
5. На netlab VM обновить deps (`cryptography >=44`), выполнить P3-07/P3-08/P3-09
   scenarios и весь netlab. Новый smoke не заменяет четыре VM/E2E-05 P3-10.
6. Отдельно исправить 2 clock tests; зелёный make check, Docker build/size и прежние
   P2 хвосты остаются обязательными. P3-10 — только после решения владельца о приёмке.

### Локальный инструментарий

Serena Python LSP упал на скачивании Pyright. По просьбе владельца пакет установлен
в uv cache offline и проверен, ignored `.serena/project.local.yml` подготовлен на
Zed BasedPyright. MCP был завершён для перезапуска, но Zed не восстановил соединение:
нужен Restart у `serena-context-server` в Zed. Работа выполнена файловыми tools и
реальными lint/type/tests. Создана ignored `.venv` с system-site-packages и
cryptography 45.0.7, системная 43.0.0 не менялась. Это локальное окружение, не tracked
часть P3-09; dependency minimum 44 зафиксирован в pyproject.

## P3-10 — disposable four-VM E2E harness (дополнение, 2026-10-17)

Подробно: [P3-10-REVIEW.md](P3-10-REVIEW.md), D-58 (**pending implementation
choice**), [операционный runbook](../runbooks/vm-e2e.md), spec 09.
**Реализован harness; задача/фаза НЕ принята и НЕ Done.** Владелец разрешил
реализацию до ревью P3-07/08/09, не отменял их приёмку.

- `tests/e2e/`: env-only inventory, pinned SSH, fixed quoted stdlib worker,
  secret stdin, exact destructive ACK + pytest switch. Root-owned per-role /
  machine-ID markers, четыре разные VM и runner на hub; exclusive non-expiring
  leases, allowlisted actions/cases и guarded explicit recovery.
- Build обоих образов один раз на hub, bounded private-file save/SSH load;
  Docker pinned local rootful socket + default builder. Fresh per-case Compose,
  NET_ADMIN/NET_RAW/TUN **container netns**, без privileged/host PID/Docker socket.
  Case metadata/config/Compose **RO**, writable только state/recovery submounts.
- Independent container-ID-specific fault watchdog, finally cleanup/diagnostics
  даже при partial setup/artifact failure, atomic private recovery ledger,
  summaries и sanitized bounded agent diagnostics. Нет global prune/host flush.
- 10 opt-in сценариев: E2E-01…06; NL-10 route repair, NL-11 signed bad-bundle
  rollback/report, NL-12 real signature tamper, **partial** NL-13 (10 min outage,
  cache boot/ext tunnel + ICMP). Ни один из них здесь на VM **не выполнялся**.
- Revoke проверяет реальный mTLS HTTP 403 через test-only TCP relay 18444;
  chain/client cert verification сохранены, hostname check отключён только
  для relay probe. Это не production listener/TLS configuration.
- Restore включает announced rotation keys, advance version, stopped owned hub
  data wipe, staged activation и старые certificates/high-water recovery. Архив
  и passphrase остаются на VM. Runtime permissions/reconnect ещё не доказаны.
- E2E-06 стартует на fresh compatible previous digest-pinned images, затем
  current; наблюдает continuous **fabric probes**, не client forwarding.
  Отсутствие baseline — explicit skip, одинаковые images — ошибка.
- 12 P4 blockers/skips не скрыты: E2E-07, NL-01…09, полный NL-13 client forwarding,
  E2E-06 client continuity. Оба agent container за Docker NAT: это не acceptance
  public agent-b / VM-level NAT ACL / production host-network topology.
- Workflow: manual confirmation / same-repo `e2e` label, protected Environment,
  singleton/no-cancel, no `pull_request_target`, no persisted checkout credentials.
  Private SSH files, local tests, always recovery / narrow upload / key removal.
  Environment protection настраивает владелец; variable ACK не создаёт защиты.
- `make e2e-plan` offline; `make e2e` opt-in; normal `make check` skips VM tests
  и теперь включает strict harness mypy. No AppConfig/GUI/dependencies/parity additions.

### Итоговая локальная проверка после P3-10

- `pytest tests/test_e2e_harness.py tests/e2e tests/test_parity.py -q`:
  **53 passed, 22 skipped**, 2.01 s: 49 local mocked safety tests + 4 parity.
  Это **не** 53 VM-прохождения. Inventory/SSH/Docker в safety tests фальшивые.
- Ruff backend/tests **passed**; harness mypy strict **9 files passed**;
  `make e2e-plan` **passed**, `network_actions:false`.
- Полный `make check` (`.venv/bin/python`, Python 3.13.5): ruff **passed**,
  mypy backend **135 files passed**, harness **9 files passed**;
  pytest **1069 passed, 64 skipped, 2 failed**, 132.30 s. **Не зелёный check.**
- Те же два `tests/test_enrollment.py` failures (`test_renew_only_after_two_thirds_and_keeps_old_cert`,
  `test_revoke_node_crl_reload_disconnect_and_sync`): fixed clock vs certtool real
  dates; renew 409. Не исправлялись/не ослаблялись в P3-10.
- `git diff --check` и ruff format check **passed**; quoted worker command
  **33,212 bytes** (<128 KiB Linux argv limit), offline check, не VM SSH proof.
- Frontend не менялся/не перезапускался: исторические UI результаты P3-09 выше,
  mocked API, не VPN evidence. VM preflight, privileged netlab, Docker build/load /
  deployment/image size, CI/workflow и push **не выполнялись**.

### Актуальный следующий шаг — ревью, затем runtime evidence

1. Claude читает четыре REVIEW и **всё tracked/untracked дерево**. Не удалять
   предыдущую работу и не объявлять P3-07…10 принятыми по факту наличия кода.
2. Проверить D-55…58; отдельно privileged worker/SSH boundary, case ownership,
   RO mounts, failed setup/teardown, fault watchdog, recovery, sanitized artifacts,
   protected-runner trust. Явно принять/изменить container-isolated scope D-58.
3. На отдельной netlab VM — P3 agent/management/backup scenarios, затем весь
   netlab/P2 prerequisites. Отдельно clock fix и зелёный full check до push.
4. Владелец предоставляет четвёртую disposable VM/полный inventory, pins/key,
   root markers, hub runner и фактическую protected Environment; paired baseline
   images. Коммит/push/workflow run — **только отдельным разрешением**.
5. Реальный four-VM run с image IDs/size, timings, diagnostics, cleanup/recovery.
   Host-network/public topology и P4/client/leak coverage остаются отдельными
   обязательствами; local mocks/tunnel ping не заменяют packet/runtime evidence.

Serena MCP не восстановлен; file/search/terminal tools использованы без попыток
повторного LSP ремонта. Никаких коммитов/веток/merge/push или изменений сети
production/dev runtime в P3-10 не сделано.
