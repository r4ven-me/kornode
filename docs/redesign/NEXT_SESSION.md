# Prompt for the next session — открытые находки ревью, E2E через GitHub Actions, пуш

> **Состояние на 2026-10-20.** Ветка `redesign/p4-01-routed-fabric`, **запушена**, открыт PR
> https://github.com/r4ven-me/kornode/pull/1 (в `main`; ничего не влито). Локально: `make check` 1105 passed /
> 68 skipped, привилегированный netlab на VM 46 passed. На GitHub: `backend` и `frontend` зелёные; первый
> `netlab` упал на двух тестах из-за формата вывода старой nft (исправлено в `61c7d7c`, нужен перезапуск CI).
> Сделано сверх P3: P4-01/P4-02 (D-63, spike S-03 не прошёл → маршруты префиксов агентов ставит reconciler
> хаба в `main` с `proto 77`) и закрытие LOW-находок ревью (D-64). e2e `.github/workflows/e2e.yml` не запускался
> (нужны protected-ветка, environment `kornode-e2e`, секреты, раннер на hub).

Вставь всё ниже черты в новую сессию Claude Code в
`/home/lans/Cloud/Projects/public/kornode`. Начни в режиме плана.

---

Продолжаем редизайн kornode (hub+agents, один reconciler). Язык — русский, обращайся ко мне «Ivan».
Прочитай по порядку: `CLAUDE.md`, `AGENTS.md`, раздел «Дальнейшие действия» в `docs/redesign/PLAN.ru.md`,
`docs/redesign/CLAUDE-HANDOFF.md`, четыре `P3-0{7,8,9}-REVIEW.md` / `P3-10-REVIEW.md`,
`docs/redesign/DECISIONS.md` (D-55…D-62), `docs/runbooks/hub-recovery.md`, `docs/runbooks/vm-e2e.md`.
Активируй проект Serena `kornode` до поиска по коду.

## Что уже сделано (не переделывай)
- Коммиты ветки (по порядку): `a92c985` P2 tails, `bfd4401` P3-10, `51c813b` P3-09, `07301e8` P3-07,
  `619d4d0` P3-08, `3ba311e`/`f375e57`/`f9f729b` docs, `122a236` исправления по E2E (hub-образ, enroll),
  `f51fa28` исправления harness, `32cdc12` docs. Разбиение P3-07…P3-10 по путям: общие файлы
  (`cli.py`, `app.py`, `parity.yaml`, спеки, `Makefile`) лежат в коммите P3-08, поэтому **промежуточные
  коммиты по отдельности не проверялись зелёными** — зелёный только HEAD.
- Хвосты P2 закрыты (D-60): `flock` на `generated_dir/reconciler.lock` (демон на всю жизнь, in-process
  `net apply` на проход, ожидание сокета запускающегося демона вместо второго писателя);
  `Reconciler.wake_netlink` уважает backoff, явный `wake()` и синхронный `apply` — нет; тест единственного
  писателя ядра переписан на AST (`tests/test_kernel_single_writer.py`, allowlist универсальных раннеров);
  netlab-сценарий D-32 (`test_established_flow_of_a_removed_exit_never_reaches_the_uplink`: с правилом
  stale-marks 0 пакетов на uplink, без него 2).
- Ревью 2026-10-18 (code-reviewer, security-reviewer; найденное — в `P3-0X-REVIEW.md`). Исправлено:
  `kornode-agent diag` отдавал `[redacted]` вместо архива; `credentials_set` и булевы флаги под секретными
  именами; публичные ключи и hex-дайджесты больше не маскируются; `rotate-signing-key --dry-run` считал хаб
  агентом; workflow e2e не публикует диагностические архивы агентов в артефакты публичного репозитория.
- `Dockerfile.agent` собран: 396 МБ; цель в spec 06 пересмотрена до ≤400 МБ (D-61).
- Привилегированный netlab на VM: 43 passed (весь набор, включая P3-07/08/09 и D-32).
- Четырёхмашинный E2E (D-62), запуск с hub по SSH: NL-10/11/12, E2E-01…05, NL-13 — **9 passed, 13 skipped**.
  Найдено и исправлено: `python` в hub-образе (симлинк в venv вёл на системный python → `control-api` не
  стартовал), гонка маршрута при enroll агента (теперь ждёт до 10 с), ошибки harness (`connect_script`,
  синтаксис nft, `certificates pin` без `--json`, сеть ext 10.8.0.0/24, окно 60 с на re-dial в NL-13).
- Проверки на dev-машине: `make check` — 1088 passed / 65 skipped; `make parity` — 4 passed.
  Фронтенд после правок этой сессии не прогонялся (vitest 30 passed + build были в предыдущей).

## Окружение
- Используй `.venv` (`make` подхватывает его сам): `.venv/bin/python -m pytest`, `.venv/bin/python -m mypy --strict backend`.
  Системный python не годится (нет `argon2` в `cryptography`). Не гоняй `ruff format` по всему репо
  (проект проверяет `ruff check`).
- Все команды на VM — через `bash`, не zsh (zsh не разбивает переменные с аргументами `ssh`).
- SSH на VM: пользователь `lans`, ключ `~/.ssh/id_ed25519`, `-o IdentitiesOnly=yes` (иначе «Too many
  authentication failures»), passwordless sudo. Синхронизация дерева: `rsync -a --delete` с исключением
  `/artifacts`, `.git`, `.venv`, `node_modules`.
- **Одноразовые VM для E2E** (владелец подтвердил, что они одноразовые): hub `192.168.122.123`,
  agent-a `192.168.122.211`, agent-b `192.168.122.26`, ext `192.168.122.202`. На них стоят Docker
  (`docker.io docker-cli docker-compose docker-buildx`), `/etc/kornode-e2e-vm.json` с ролями, на hub —
  выделенный ключ `~/.e2e/id_ed25519`, `~/.e2e/known_hosts`, `~/.e2e/env.sh`, venv в `~/kornode/.venv`,
  swap 2 ГБ на hub и ext (apt иначе убивался по OOM при 2 ГБ RAM). Старый netlab-стенд
  `192.168.122.30` в конце сессии был недоступен («No route to host»).
- Запуск E2E на hub: `. ~/.e2e/env.sh; export TMPDIR=/var/tmp` (`/tmp` — tmpfs 1 ГБ, архив образов не влезает),
  затем `.venv/bin/python -m tests.e2e preflight` и `.venv/bin/python -m pytest tests/e2e --e2e-run -q --tb=short`.
  Полный прогон ≈ 29 минут (NL-13 — 10 минут простоя хаба). После падения: `python -m tests.e2e cleanup --all-owned --yes`.
- Первая сборка образа после смены исходников требует работающего PyPI; на VM сеть нестабильна, дважды
  сборка падала с «local image command failed» и проходила со второй попытки (слои в кэше).
- Диагностика harness намеренно скрыта (`output withheld`); для разбора падения временно писали stderr
  `transport._invoke` и `worker.run` в файл на VM — в репозиторий это не попадало. Тест NL-13 теперь
  печатает состояние туннелей в сообщении assert (`Cluster.upstream_summary`).

## Что делать дальше (по порядку)
1. ~~Открытые LOW-находки ревью 2026-10-18~~ — закрыты в D-64.
2. **Плавающий E2E-04** («revocation incomplete; node is fail-closed; retry revoke», `committed: true`):
   один раз упал, в одиночку и в двух чистых прогонах проходил. Причину не нашли — подробностей нет, они
   в аудите хаба (`agent.revoke`, `details.failures`), а контейнеры после падения удалены. Воспроизвести
   циклом E2E-04 с копированием `audit.jsonl` хаба по ходу прогона (подозрение: шаги `reload ocserv` /
   `disconnect` сразу после старта хаба).
3. **E2E-06 (обновление):** нужны пара совместимых предыдущих образов по digest'у
   (`E2E_PREVIOUS_HUB_IMAGE`, `E2E_PREVIOUS_AGENT_IMAGE`) — их ещё нет; попросить у владельца или собрать
   из предыдущего коммита с публикацией на локальный реестр.
4. **Прогон через GitHub Actions** (`.github/workflows/e2e.yml`, self-hosted runner на hub): только после
   разрешения владельца на push. Нужны: ветка с protected-веткой, GitHub Environment `kornode-e2e` с approval,
   секреты `E2E_SSH_KEY`, `E2E_SSH_KNOWN_HOSTS`, переменные `E2E_*_HOST`, `E2E_SSH_USER`,
   `E2E_ENVIRONMENT_APPROVAL_CONFIGURED=true` (только при реально настроенной защите), runner group.
   Также впервые прогнать CI-задачу `netlab` на GitHub-раннере.
5. **Решение владельца про push:** варианты — ветка `redesign/p2` + один PR в `origin/main` со списком
   P2-01…P2-11 (предпочтительно), либо push напрямую; затем PR'ы P3. Локальный `main` опережает
   `origin/main` на 44 коммита.
6. Дальше по `ROADMAP.md` — фаза P4 (маршрутизируемая фабрика; её сценарии в `tests/e2e/test_routed_fabric.py`
   пока skip с причинами).
7. Обновить `PLAN.ru.md`, `ROADMAP.md`, `CHANGELOG.md`, этот файл; отчёт по формату из `CLAUDE.md`.

## Что нужно от меня (напомни заранее)
Разрешение на push и запуск через GitHub Actions; digest'ы предыдущих образов для E2E-06 (или решение,
как их получить); решение по оставшимся LOW-находкам (чинить сейчас или оставить в REVIEW-файлах);
если нужен netlab — рабочий стенд (`192.168.122.30` недоступен, либо поднять netlab на одной из
одноразовых VM, там нужны `ocserv openconnect nftables tcpdump gnutls-bin iproute2`).

## Правила
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make check` → netlab; `parity.yaml` обновляется
в той же задаче. Тесты не ослаблять; если тест кодирует убираемое поведение — удалить в том же PR и сказать
об этом. Значимые изменения — локальным коммитом (без push), `--no-verify` не использовать.
