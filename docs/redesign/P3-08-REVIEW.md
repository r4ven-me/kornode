# P3-08 — передача основному Claude-агенту на ревью

Дата: **2026-10-16**. Накопительный индекс: [Передача Claude](CLAUDE-HANDOFF.md).

## Состояние / scope

Владелец согласовал реализацию P3-08 в `redesign/p3-08-agent-management`, включая
control status/signing rotation. Рабочее дерево содержит **незакоммиченные P3-07
и P3-08**. Ничего не commit/merge/push без отдельного разрешения. Новые untracked
файлы входят в реализацию и должны попасть в review, а не только `git diff`.

Реализация готова к ревью, **не окончательная приёмка**: privileged netlab ещё не
запускался. Писал один вспомогательный агент без субагентов; финальное ревью и
продолжение — основному Claude. Предыдущая передача P3-07 сохранена отдельно.

## Что сделано

### Общие сервисы и реестр

- `backend/kornode/services/agent_models.py`: общие строгие модели запросов,
  `ManagementError(status,error,message,details)`, ограничения на credentials,
  запрет неподдерживаемого runtime (p12/pushed routes).
- `backend/kornode/services/agents.py`: единый фасад management для CLI/API:
  - CRUD, выделение ID 2…254 (1 — hub), явный force reuse, 30-day quarantine;
  - enrollment issue/revoke, revoke **до** delete, отказ delete при частичном отзыве;
  - management flock с таймаутом 5 s; mutation/validation/compile_all в транзакции,
    sync после commit; посткоммитная ошибка явно `committed:true`;
  - prefixes, policy, source/upstream CRUD; shared model/compiler/address overlap
    validation; source pool/interface checks, сохранение несвязанных manual prefixes;
  - upstream passwords/private keys/camouflage и fabric camouflage encrypted at rest
    через существующий master key; credentials write-only, ciphertext также не выдаётся;
  - access-user CRUD с ocpasswd-хешем через приватный temporary файл (без записи
    в парольный файл хаба); omitted groups/enabled сохраняются при смене пароля;
  - latest reports/online, safe bundles/history/diff, typed commands/expiry/cap 100,
    owner-bound results, archive metadata без base64 и отдельный download ≤5 MiB.
- `backend/kornode/registry/migrations/0002_agent_management.sql`: schema 2,
  `node_id_quarantine` и `control_rotation`; repository accessors.
- `backend/kornode/services/control_management.py`: status и staged rotation.
  Семь дней old-signed `next_signing_pubkey`, затем новый signer; active/next paths
  и start time в SQLite. Atomic key files, fsync directory, no deletion old keys.
  Повторная rotation во время окна — conflict; dry-run не создаёт ключи.
- `BundleService` учитывает encrypted camouflage, announcement и signer в dedup;
  control poll обновляет rotation bundle без обязательной новой config mutation.

### Отзыв и синхронизация

- `AgentService` передаёт EnrollmentService callback `occtl reload`, независимый
  от supervisor (netlab запускает ocserv непосредственно).
- `EnrollmentService.revoke_node` больше не игнорирует сбой отключения живого агента.
  `SessionService.disconnect_if_present` сначала отключает, а при ошибке принимает
  только valid empty JSON `show user` с кодом 0/2 как доказанное отсутствие.
  Недоступный сервер, invalid JSON/shape или оставшаяся сессия — failure; запись
  остаётся revoked, delete не происходит. Это делает повторный отзыв offline
  агента допустимым, не превращая командную ошибку в ложный успех.
  Семантика occtl подтверждена чтением upstream `src/occtl/unix.c`, runtime ещё проверить.
- `FabricGroupsService.sync` и `ConfigService.write_rendered_files` разделяют flock
  `generated_dir/.fabric-groups.lock`; lock берётся **перед** чтением registry snapshot
  и удерживается до записи/cleanup. Старый concurrent snapshot не может воскресить
  удалённый per-user guard. Fabric-disabled старый путь не меняется.

### Интерфейсы / parity

- `backend/kornode/cli_agents.py`: 37 leaf-команд `agent`/`control`, JSON,
  табличный list, hidden prompt/stdin для access-password (не argv).
  Revoke/delete/rotation и remote reconnect/restart/rollback требуют confirmation
  или `--yes`; в JSON — неинтерактивный отказ без флага. Dry-runs доступны для
  create/revoke/delete/enqueue/rotation. `egress edit` через click editor.
- `backend/kornode/api/routes_agents.py`: 32 admin endpoints, существующие admin
  auth/CSRF, bounded JSON body 1 MiB, sanitized errors. Router подключён в app;
  все management responses, включая ошибки/downloads, no-store.
- `frontend/src/agentsApi.ts`, `frontend/src/views/agents/*`: Agents list/detail,
  create/enroll token dialog, settings, networks/sources, policy editor,
  upstreams, registry access users, reports/versions/commands/results/artifacts,
  control status/rotation. Общие существующие request helpers экспортированы.
- `parity.yaml`: 39 новых capability rows, ни одного нового exemption.
- `backend/kornode/bundle/redaction.py`: извлечён общий Redactor из agent inspection;
  агент не импортирует hub services, импортные границы сохраняются.
- Новых AppConfig полей и зависимостей нет. Specs 05/08, D-56, changelog,
  roadmap/plan/NEXT_SESSION и накопительная передача обновлены.

## Границы, которые нельзя выдавать за готовый P4 runtime

- Access users сохраняются **только в registry**. В bundle access ещё не emitted
  (D-48), local ocserv authentication/доставка — P4-04. UI/API явно это сообщают.
- Access/exit роли и exported prefixes — подготовка входов, не proof of connectivity.
- Domain/URL resolution, p12, pushed routes и `via exit:N` отклоняются как
  unsupported, а не тихо принимаются как работающие. Их реализация не входит в P3-08.
- Политика — ordered structured rule controls + JSON destination/sets; полный
  polished editor — P5. Пользователь всё равно видит реальные P3 возможности.
- CLI/control plane работают с `web.enabled:false`; admin HTTP endpoints требуют
  включённого optional web/API. Нет нового открытого management listener на агенте.
- No new kernel writer: management меняет registry/files и вызывает process controls;
  routes/rules/nft/sysctl остаются только за `kornode.net`.

## На что смотреть при ревью

1. **Secret boundary:** explicit create/reissue возвращает one-time token по spec05;
   это намеренное исключение, не logs/list API. Panel dialog masked/ephemeral,
   copy явный, browser storage не используется. Clipboard не очищается автоматически.
   Просмотреть normal views/errors/history/diff, sealed objects, private PEM и hashes.
2. **Transactions / partial operations:** create может уже создать node, но не token;
   sync может упасть после commit. Клиент обязан читать committed details, не повторять
   blindly create. Revoke fail-closed state сохраняется при поздних сбоях, retry явный.
3. **Concurrency:** management lock + SQLite transaction; group render/sync lock
   до snapshot. Control API/enrollment тоже пишут registry, поэтому SQLite остаётся
   общим каналом и нельзя считать management flock универсальной блокировкой DB.
4. **ID reuse:** карантин лишь после полного отзыва, force не переиспользует live ID.
   CRL содержит все выданные сертификаты. Повторный offline revoke/delete корректен.
5. **Signing rotation:** announcement/confirmation, persisted paths, promotion на
   polling, dedup version bump, несколько последовательных ротаций, пропущенное окно.
   Владелец предупреждён об offline reenrollment. Old keys не удаляются.
6. **P3-09 backup dependency:** DB + master/CA + **все referenced private key paths**,
   включая кастомные вне data_dir. Архив только исходного signing.ed25519 потеряет identity.
7. **Remote command safety:** только фиксированные аргументы, ownership при result
   и download, expiry/cap, queue ≠ done; архив не извлекается хабом, файл CLI no-clobber.
8. **UI:** global preview блокирует операции без API dry-run; actual dangerous actions
   названы/подтверждаются. Reports/commands polling не должен затирать drafts.
   Проверить длинные имена, revoked/pending states, secret reset/unmount.

Фасад agents.py получился крупным (~800 строк). Декомпозиция возможна после ревью,
но не стоит превращать её в переписывание работающего контрактного слоя до приёмки.

## Проверки

Локально Linux, uid 1000, Python 3.13.5. Не запускалась привилегированная сеть.

- Новые backend suites: `test_agent_management`, `test_agent_management_surfaces`,
  `test_agent_management_sync`, `test_agent_revocation`, `test_control_management`:
  **35 passed**. В том числе matrix всех 32 admin endpoints без auth, все mutating
  endpoints с cookie без CSRF, body cap/no-store, malformed/oversized artifacts,
  transactional rollback, quarantine, ownership, redaction, sync race, disconnect proof.
- `make check PYTHON=python3`: ruff passed; strict mypy passed (**130 source files**);
  pytest **983 passed, 41 skipped, 2 failed**, 114.11 s. Полный check **не зелёный**.
- Оба failures прежние: `tests/test_enrollment.py::test_renew_only_after_two_thirds_and_keeps_old_cert`
  и `::test_revoke_node_crl_reload_disconnect_and_sync`. Fixed clock 2026-10-13
  расходится с реальным certtool issuance; failure в `renew` (409), до assertions
  отзыва не доходит. В этой задаче эти тесты не менялись/не ослаблялись.
- `make parity PYTHON=python3`: **4 passed**. `git diff --check`: passed.
- Vitest: **23 passed**, из них 4 Agents component cases. `npm run build`: passed.
- `npm run test:e2e -- agents.spec.ts --workers=2` из frontend: **4 passed**,
  настоящий Chromium, 1440×900/390×844, light/dark. Нет body overflow,
  кнопки ≥40/44px, primary contrast ≥4.5, focus, no alert/page errors;
  screenshot upstream form/access users. Desktop-light и mobile-dark проверены визуально.
  Общий mock DNS fixture дополнен недостающим `upstreams`, а не подавлен toast в production.
- Browser использует **mocked admin API**, это не 4-VM fabric e2e и не end-to-end
  backend enrollment через GUI. Эти уровни покрытия не смешивать.
- `tests/netlab/test_p3_management.py`: **1 skipped** (нет root/ocserv);
  сценарий существует, но runtime ещё не подтверждён.

## Обязательный privileged netlab перед приёмкой

На подготовленной изолированной VM, **не на production/dev машине**:

```sh
python3 -m pytest tests/netlab/test_p3_management.py -v
python3 -m pytest tests/netlab/test_p3_agent.py -v
make netlab PYTHON=python3
make parity PYTHON=python3
```

Новый management smoke с настоящим ocserv/ocpasswd и web disabled:
create dry-run → create/token → list/show без token → reissue/revoke token →
revoke/delete dry-run → offline revoke → delete → quarantine refusal → control
status/rotation preview. Весь netlab дополнительно проверяет live certificate
revocation, группы и новый агент. Исправить при необходимости, не объявлять skip успехом.

P3-09/P3-10, Docker image build/size, CI push и P2 хвосты **не выполнялись**.
После review/netlab и отдельного исправления двух clock tests — полный check;
только затем принятие задач и продолжение P3-09 по решению владельца.

## Повторное ревью 2026-10-18

- **Исправлено (MEDIUM):** `credentials_set` в списке upstream всегда был `"[redacted]"` — редактор
  прятал булевы значения под секретными именами; теперь булевы флаги читаемы. Ключи `*otp*`/`*session*`
  сопоставляются по границе слова (`footprint`, `sessions` больше не маскируются).
- **Исправлено (LOW):** `control rotate-signing-key --dry-run` считал хаб агентом.
- **Закрыто (D-64):** `_validate` в `AgentService` перебирает все неотозванные узлы, поэтому устаревшая
  политика одного агента (записана до ужесточения проверок) блокирует правки другого с 409; `revoke`/`delete`
  не блокируются.
- **Сверено (INFO, D-64: менять нечего — `revoke_node` пишет аудит и при неудаче, `outcome=failure`):** `AgentService.revoke`/`token` сами не пишут аудит — запись делает `EnrollmentService`;
  проверить все ветки, включая неудачный отзыв.
- **Ниже порога (security, LOW):** хаб отдаёт оператору диагностический архив от агента без проверки,
  что это tar.gz с плоскими безопасными именами; зафиксировать как недоверенный или проверять формат.
