# Prompt for the next session — слияние PR #1, P4-03…P4-07, E2E через GitHub Actions

> **Состояние на 2026-10-20.** Ветка `redesign/p4-01-routed-fabric` **запушена**, открыт PR
> https://github.com/r4ven-me/kornode/pull/1 в `main` (**не влит**, ревью и слияние — решение владельца).
> Последний коммит ветки: `7713cac`. CI на PR зелёный: `backend`, `frontend`, `netlab` (первый успешный
> `netlab` на GitHub-раннере). Локально: `make check` 1105 passed / 68 skipped, `make parity` 4 passed.
> Привилегированный netlab на VM hub: 46 passed. Четырёхмашинный E2E: NL-01 и NL-04 (case `routed`) —
> passed; остальной набор последний раз гонялся на прошлом HEAD (9 passed, 13 skipped, D-62).
> Сделано: P2…P3-10, P4-01, P4-02, закрытие LOW-находок ревью. **Не сделано:** P4-03…P4-07, E2E-06,
> прогон `e2e.yml` на GitHub Actions, расследование плавающего E2E-04.

Вставь всё ниже черты в новую сессию Claude Code в
`/home/lans/Cloud/Projects/public/kornode`. Начни в режиме плана.

---

Продолжаем редизайн kornode (hub+agents, один reconciler). Язык — русский, обращайся ко мне «Ivan».
Прочитай по порядку: `CLAUDE.md`, `AGENTS.md`, `docs/redesign/ROADMAP.md` (фаза P4), раздел «Дальнейшие
действия» в `docs/redesign/PLAN.ru.md`, `docs/redesign/DECISIONS.md` (D-55…D-65), `docs/spec/07-fabric.md`,
`docs/runbooks/vm-e2e.md`. Активируй проект Serena `kornode` до поиска по коду.

## Что уже сделано (не переделывай)
- **P2 tails, P3-07…P3-10** (D-55…D-62): CLI агента, управление агентами на хабе (CLI/API/панель), backup/restore,
  E2E-harness на 4 VM. Подробности и ревью — `P3-0X-REVIEW.md`.
- **P4-01/P4-02** (D-63, D-65):
  - Per-user файлы ocserv (`FabricGroupsService.render_files`): `explicit-ipv4`, `iroute` для экспортируемых
    префиксов узла, `route` для чужих, `dpd`/`keepalive` узла. `occtl reload` только при изменении
    существующего файла. `export=false` не попадает никуда. `dpd`/`keepalive` действуют только на хабе.
  - **Spike S-03 не прошёл:** ocserv не ставит маршруты `iroute` без `route-add-cmd` (это сделало бы его
    вторым писателем в ядро). Поэтому reconciler хаба ставит `<prefix> dev vpnsN` в таблицу `main` с
    `proto 77` (`KORNODE_RTPROTO`, `Route.proto`, `NodeFacts.session_routes`, `HubNetInputs._session_routes`).
    Сессия считается подключённой, пока `10.99.0.<id>` — маршрут на `vpns*` в `main`. Владение `main`
    только по протоколу: `kernel._parse_route` и `owns_route` игнорируют любые другие маршруты.
  - Тест «нет NAT к fabric» (`tests/test_net_compile.py`), netlab `test_spike_p4_iroute.py` и
    `test_agent_prefix_route_in_main_is_owned_by_protocol_and_withdrawn`.
  - **E2E NL-01** (хаб → агент по fabric, source `10.99.0.1`) и **NL-04** (агент-a → LAN агента-b через
    хаб, source = fabric-адрес агента-a): оба passed на четырёх VM. Трафик хоста агента обязан идти с
    fabric-адресом как source (иначе хаб отбрасывает строгим RPF, D-47). Клиентский путь (cli3 в spec 09)
    возможен только с ролью `access` из P4-04.
  - Harness: действия `fabric_address`, `lan_setup`, `export_prefix`, `fabric_listen`, `fabric_connect`,
    `net_dump` (маршруты/правила/nft без секретов печатаются в сообщении падения `Cluster.tcp_peer`).
- **LOW-находки ревью 2026-10-18 закрыты (D-64):** backup нового хаба (мастер-ключ создаётся, пока ничего не
  запечатано), `OSError` → `503 backup_io`, `_validate` проверяет политику только изменяемого узла, кэш
  `doctor` в отчёте агента (120 с по версии), проверка формата diag-архива на хабе, netlab принимает оба
  формата вывода nft (1.0 и 1.1).
- Остаётся 10 skip в `tests/e2e/test_routed_fabric.py`: E2E-07, NL-02, NL-03, NL-05…NL-09, NL-13-forwarding,
  E2E-06-clients (причины — в самом файле).

## Окружение
- Используй `.venv`: `.venv/bin/python -m pytest`, `.venv/bin/python -m mypy --strict backend`,
  `.venv/bin/python -m ruff check backend tests` (не `ruff format` по всему репо). Системный python не годится.
- Shell пользователя — zsh: переменные с аргументами `ssh` не разбиваются. Используй функцию
  `vm() { ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 lans@192.168.122.123 "$@"; }`.
- `gh` установлен и залогинен (аккаунт `r4ven-me`, протокол SSH); `git push` по SSH работает. Push, merge,
  запуск workflow — только по явному разрешению владельца в чате.
- **Одноразовые VM:** hub `192.168.122.123`, agent-a `.211`, agent-b `.26`, ext `.202`. SSH: пользователь
  `lans`, ключ `~/.ssh/id_ed25519`, `-o IdentitiesOnly=yes`, passwordless sudo. Синхронизация дерева на hub:
  `rsync -a --delete` с исключением `/artifacts`, `.git`, `.venv`, `node_modules` в `~/kornode/`.
  Старый netlab-стенд `.30` недоступен; **netlab гоняется на hub-VM** (там поставлены `ocserv openconnect
  nftables gnutls-bin`, есть `tcpdump iproute2`): `sudo -n .venv/bin/python -m pytest -m netlab -q`
  из `~/kornode` (полный набор ≈ 6,5 мин, 46 passed).
- **E2E на hub:** `. ~/.e2e/env.sh; export TMPDIR=/var/tmp`, затем `.venv/bin/python -m tests.e2e preflight`
  и `.venv/bin/python -m pytest tests/e2e/test_routed_fabric.py --e2e-run -q --tb=short` (оба P4-кейса ≈ 5 мин;
  весь набор ≈ 29 мин). Запускай в фоне (`nohup ... > /var/tmp/x.out`) и жди по `grep` в файле вывода,
  а не по `pgrep -f` (он находит собственную команду). После падения:
  `python -m tests.e2e cleanup --all-owned --yes`.
- Сборка образа на VM после смены исходников требует рабочего PyPI и иногда падает «local image command
  failed» за ~20 с; помогает повторить (слои в кэше) или собрать `docker build --builder default --file
  Dockerfile[.agent] .` вручную на hub.
- Вывод harness намеренно скрыт (`output withheld`). Для разбора сетевых падений используй `net_dump`.

## Что делать дальше (по порядку)
1. **PR #1** ждёт ревью владельца. Он большой (≈90 коммитов; промежуточные коммиты по отдельности не
   проверялись зелёными — зелёный только HEAD). Без слияния новые PR строить не на чем.
2. **P4-03 … P4-07** (`ROADMAP.md`, `docs/spec/07-fabric.md`): DNS по зонам узлов, роль `access`, источники
   (wg-easy/Amnezia), `via: exit:<node>`, панель/CLI/API фабрики. Каждая задача: spec → тесты → код →
   docs → `make check` → netlab → (E2E там, где задача трогает data plane); `parity.yaml` обновляется в той же
   задаче. Каждому E2E-кейсу из списка skip нужен реальный сценарий, не заглушка.
3. **Плавающий E2E-04** («revocation incomplete; node is fail-closed; retry revoke», `committed: true`):
   один раз упал, в одиночку и в двух чистых прогонах проходил. Причина не найдена; подробности в аудите
   хаба (`agent.revoke`, `details.failures`), контейнеры после падения удалены. Воспроизвести циклом E2E-04
   с копированием `audit.jsonl` хаба по ходу прогона (подозрение: `reload ocserv` / `disconnect` сразу
   после старта хаба).
4. **E2E-06 (обновление):** нужна пара совместимых предыдущих образов по digest'у
   (`E2E_PREVIOUS_HUB_IMAGE`, `E2E_PREVIOUS_AGENT_IMAGE`) — их нет; попросить у владельца или собрать из
   предыдущего коммита и положить в локальный реестр.
5. **Прогон `e2e.yml` на GitHub Actions** (self-hosted runner на hub): нужны protected-ветка, Environment
   `kornode-e2e` с approval, секреты `E2E_SSH_KEY`, `E2E_SSH_KNOWN_HOSTS`, переменные `E2E_*_HOST`,
   `E2E_HUB_ADDRESS`, `E2E_SSH_USER`, `E2E_ENVIRONMENT_APPROVAL_CONFIGURED=true` (только при реально
   настроенной защите), runner group с меткой `kornode-e2e`. Настраивает владелец.
6. Обновлять `PLAN.ru.md`, `ROADMAP.md`, `CHANGELOG.md` и этот файл вместе с изменениями; отчёт — по формату
   из `CLAUDE.md` (что изменилось, ID задач, доказательства тестами, записи в `DECISIONS.md`).

## Что нужно от меня (напомни заранее)
Ревью и слияние PR #1 (или решение резать его на части); разрешение на push следующих веток и на запуск
workflow; настройка GitHub (protected-ветка, environment, секреты, runner) для `e2e.yml`; digest'ы
предыдущих образов для E2E-06 или решение, как их получить.

## Правила
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make check` → netlab. Тесты не ослаблять; если
тест кодирует убираемое поведение — удалить/обновить в том же PR и сказать об этом. Значимые изменения —
локальным коммитом, `--no-verify` не использовать. Ядро трогает только `kornode.net`.
