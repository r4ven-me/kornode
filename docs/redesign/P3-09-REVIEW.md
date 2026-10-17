# P3-09 — передача основному Claude-агенту на ревью

Дата: **2026-10-16**. **Реализовано, но не принято окончательно.**
Владелец прямо поручил продолжить P3-09 аналогично P3-08, поверх текущего дерева.
Согласование/приёмка P3-07/P3-08 этим **не подменяются**. Никаких коммитов,
новых веток, merge или push. Ветка осталась `redesign/p3-08-agent-management`;
P3-07/P3-08/P3-09 — вместе в незакоммиченном дереве, включая untracked files.
Работал один implementer, без субагентов. Накопительный документ:
[CLAUDE-HANDOFF.md](CLAUDE-HANDOFF.md); предыдущие REVIEW сохранены.

## Что реализовано

- `backend/kornode/services/backup.py`: общий `BackupService.create/restore`,
  ограничение одновременных операций flock, serialization с P3-08 management,
  SQLite backup под writer reservation, source-change detection. Backup только
  инициализированного fabric hub; restore может работать без запущенного control API.
- `backup_crypto.py`: фиксированный `.knbackup` v1 envelope, Argon2id 64 MiB / t3 /
  p4 / key32, salt16, nonce12, ChaCha20-Poly1305, весь header в AAD. Нет
  attacker-controlled параметров KDF, сжатия, tar extraction или новых библиотек.
  **Минимум `cryptography` поднят 42 → 44** (Argon2id); локально проверено с 45.0.7.
- `backup_state.py`: строгий ограниченный manifest, base64 records + SHA-256,
  allowlisted portable roots, проверка path traversal/дубликатов parent-file,
  permissions, SQLite integrity/foreign keys/forward-only schema и identity coverage.
- DB сохраняется с committed WAL, а не копированием основного inode без WAL.
  Сохраняются resolved AppConfig, CA/серверный TLS, master key **из фактического
  `data_dir/control/master.key`**, secrets/ocpasswd/OATH, certs/agents/users, persisted
  control keys, user/group configs и typed external file refs.
- **Зависимость P3-08 выполнена:** configured signing key + оба DB-referenced
  `active_path`/`next_path` ротации, в том числе custom вне data_dir. Есть тесты
  объявления, promotion/повторной ротации и восстановления key pointers.
- Restore проверяет всё до записи целевого дерева; захватывает **новый** каталог
  exclusively, файлы пишет атомарно, `config.yaml` — последним. При ошибке удаляет
  только созданное этой операцией дерево. В существующий каталог не восстанавливает.
- Все типизированные config paths и registry rotation pointers переназначаются в
  новый root; canonical bundle bytes/signatures и encrypted credentials не меняются.
  Managed ocserv hook **регенерируется с новыми user paths**, а не архивируется
  со старыми абсолютными путями. Custom hooks сохраняются как external file refs.
- CLI `cli_hub.py`: `hub backup --out`, `hub restore <file> --target --dry-run --yes`,
  `--json` на обоих; hidden prompt или `--passphrase-file`, **нет secret argv/env flag**.
  JSON требует файл passphrase, не подвисает на prompt; ошибки sanitized.
  Зашифрованный output атомарно публикуется 0600 с no-clobber даже на symlink.
- Admin API `routes_hub.py`: CSRF + existing auth, bounded JSON backup input,
  streaming encrypted download, bounded raw ciphertext restore upload; no-store
  для успешных ответов и ошибок. Restore по умолчанию validate-only;
  staging требует `dry_run=false&confirm=restore`, target пользователь API не задаёт.
- Панель **Config → Backup / Restore**, `hubApi.ts`: masked ephemeral passwords,
  подтверждение backup passphrase, download, upload → validation → отдельное
  staging confirmation. После каждого запроса password очищается, не сохраняется
  в browser storage. Global dry-run запрещает staging. Desktop/mobile, light/dark.
- `parity.yaml`: **2 новых capability без exemptions**, все поверхности через сервис.
  Новых `AppConfig` fields / scheduler / retention settings нет.
- [Runbook](../runbooks/hub-recovery.md), D-57, specs 05/08/11, README/changelog,
  roadmap и prompts обновлены; задача не отмечена Done.

## Важные границы — ревью должно их явно принять или потребовать доработку

1. **Restore = staged recovery, не live switch.** Безопасной общей атомарной замены
   SQLite + config + secrets для всех supervisor workers нет. Сервис не трогает
   runtime, сеть, работающие listeners, старые файлы и volumes. Оператор отдельно
   fence/останавливает старый hub, активирует mounts/config и запускает runtime.
   Это implementation choice D-57, не ранее утверждённый владельцем live-restore UX.
2. **Не заявлен универсальный atomic hot backup.** DB/rotation и P3-08 management
   сериализованы; изменения inode/size/mtime/ctime/директорий во время capture
   обнаруживаются и отказывают backup. Legacy config/user/OTP/CA/external writers
   не все имеют общий transaction barrier; runbook требует maintenance-window
   quiescence. Гонка с произвольным writer за пределами этого контракта не доказана
   невозможной. Не выдавать source stat checks за межсервисную транзакцию.
3. Staging root **0700**, config/private material 0600. Для activation worker'ам
   ocserv нужен traversal root (в runbook явный `chmod 0711`) и normal startup,
   который устанавливает generated/user/group directory permissions. Readable
   user/group files сохраняют 0644; custom hooks — нужный execute mode. Это важно
   проверить на реальном ocserv, а не только Python-чтением файлов от root.
4. Typed paths и DB pointers remap'ятся; пути внутри arbitrary custom script/raw
   ocserv text не угадываются. Compose/PAM/RADIUS/ACME deployment/system packages/
   static image assets отдельно. Explicit TLS symlinks materialize'ятся; recursive
   links/special files отклоняются. Exclusions перечислены в runbook.
5. Фиксированные limits: encrypted archive ≤128 MiB, ≤10,000 records, raw capture
   <64 MiB; JSON/base64 и crypto требуют RAM. Один expensive worker на data_dir;
   auth обязателен, reverse proxy тоже должен ограничивать request sizes и не
   логировать body/passphrase header. Upload passphrase base64 header — **не шифр**,
   только HTTPS. Он не попадает в URL или штатный audit.
6. DB scratch находится на диске в временном 0700 каталоге, удаляется штатно;
   payload/config bytes в memory до explicit restore. Crash remnants/своп требуют
   защищённого temp storage, zeroization Python immutable bytes не заявляется.
7. Старый backup неизбежно теряет последующие revocations/password changes/policies.
   Их надо reconcile до допуска traffic; stale CRL не надо «лечить» очисткой списка.
   D-37/D-52 high-water recovery сохранён; агентам, пропустившим всю announcement
   ротацию, всё ещё может потребоваться re-enrollment.

## Локальные результаты

- Новые `tests/test_hub_backup.py` + `test_hub_backup_surfaces.py`: **37 passed**.
  Wipe/restore identity + sealed credentials; repeated/custom rotation; no-clobber;
  corrupted/password/tamper/truncate/header/path/mode/hash/missing-key/schema errors;
  source changes, operation lock, failure cleanup, explicit TLS links, managed hook;
  actual FastAPI auth/CSRF/no-store/audit and CLI with `web.enabled:false`.
- `make parity`: **4 passed**. Совместный targeted запуск: **41 passed**.
- Последний **`make check`** (`.venv/bin/python`, Python 3.13.5, cryptography 45.0.7):
  ruff **passed**, mypy strict **passed (135 files)**;
  pytest **1020 passed, 42 skipped, 2 failed**, 133.53 s. **Не зелёный make check.**
- Те же прежние failures `tests/test_enrollment.py`:
  `test_renew_only_after_two_thirds_and_keeps_old_cert`,
  `test_revoke_node_crl_reload_disconnect_and_sync` — fixed clock против реальной
  даты certtool. Не менялись; production renewal logic не ослаблялась.
- Frontend vitest **29 passed** (6 новых: 4 panel + 2 transport), production build
  TypeScript/Vite **passed**.
- Chromium P3-09: **4 passed** (1440×900 / 390×844, обе темы, download/validate/stage,
  clear passwords, auth CSRF headers, no overflow, 40/44px buttons, primary contrast
  ≥4.5 для primary и destructive actions, focus, no page errors/alerts, screenshots).
  Проверка color-mix использует canvas RGB normalization, не ошибочное RGB-regex.
  Скриншоты desktop/light и mobile/dark просмотрены. Вместе с P3-08 browser regression:
  **8 passed**. Это **mocked API UI tests**, не VPN runtime на VM.
- `tests/netlab/test_p3_backup.py`: **1 skipped локально**, privileged не запускался.
  Не было опасных network changes или запуска production/dev runtime.
- `git diff --check`: passed. Docker image/build/size и CI push не выполнялись.

## Обязательная privileged проверка

На подготовленной **netlab VM**, после обновления dev deps (`cryptography >=44`):

```sh
sudo .venv/bin/python -m pytest tests/netlab/test_p3_agent.py tests/netlab/test_p3_management.py tests/netlab/test_p3_backup.py -v
```

Затем весь netlab. Новый backup smoke:
1. Реальный enroll/certificate/fabric poll.
2. Signing announcement; CLI encrypted backup при выключенном Web.
3. Stop только fixture listeners, wipe только guarded fixture root.
4. Staged restore; явный worker traversal/activation и normal runtime initialization.
5. Оригинальные agent cert/key и hub pin → reconnect без token/CSR/re-enroll.
6. mTLS ping; high-water poll > backup → новый monotonic bundle; rotation identity
   и `started_at` остаются прежними.

Запись root-only tree и Python verify не заменяют это исполнение. Четыре VM и
E2E-05 — P3-10, он не выполнен. Прежние P2 хвосты/Docker/clock-tests остаются.

## Инструментарий этой сессии

Serena Python LSP не стартовал: `uvx pyright==1.1.403` не мог скачать пакет с PyPI.
По просьбе владельца выполнена попытка самостоятельного восстановления: пакет
скачан через curl и offline-установлен в uv cache; executable проверен. Локальный
ignored `.serena/project.local.yml` настроен на уже установленный Zed BasedPyright.
Текущий MCP-процесс был завершён для перезапуска, но Zed автоматически не
переподключился: требуется Restart у `serena-context-server` в Zed. Разработка
продолжена обычными файловыми/search tools; lint/types/real tests не подменялись.
Локально создан ignored `.venv` с system site packages + cryptography 45.0.7,
чтобы не менять системный cryptography 43 и проверить новый минимальный API.
Пакет editable установлен в эту `.venv` без загрузки новых build deps;
`.venv/bin/korctl hub backup --help` проверен.

## Повторное ревью 2026-10-18

- **Открыто (LOW):** backup хаба без единой компиляции пакета падает `409 missing_state`:
  `control/master.key` создаётся лениво (`BundleService.master_key()`), а в `backup_state.py` он `required=True`.
  Решить: создавать ключ при инициализации фабрики либо не требовать его до первого использования.
- **Открыто (LOW):** любое неожиданное исключение в `backup.py:60-65` (в том числе `OSError`: ENOSPC, права)
  становится `422 backup_failed`; для `OSError` нужен 500/503.
