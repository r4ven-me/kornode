# Prompt for the next session — слияние PR #1, P4-04…P4-07, E2E через GitHub Actions

> **Состояние на 2026-10-20 (конец третьей сессии).** В `main` влиты PR #1 (P2…P4-02), PR #2 (P4-03, D-66), PR #3
> (P4-04, D-67, влит локальным merge-коммитом: `gh` не работает, см. память `gh-keyring-blocks-cli`) и **P4-05**
> (источники агентов, D-68; тоже локальным слиянием, PR-объекта нет). Локально: `make check` 1195 passed / 74 skipped,
> `make parity` 4 passed, frontend 33 passed. netlab на hub-VM: 52 passed. E2E case `routed` на четырёх VM:
> NL-01, NL-02, NL-03, NL-04, NL-06 — passed (NL-04 один раз упал в полном прогоне, дамп маршрутов был полным; в
> одиночку и в повторном прогоне проходит, причина не найдена); E2E-06 — passed; E2E-04 — 5 из 5. **Не сделано:**
> P4-06 (выход через узел + источники/egress хаба), P4-07 (панель/CLI/API фабрики), NL-05, прогон `e2e.yml`.
>
> **Важно для продолжения:** (1) хост перезагружался — VM `debian13-kornode1..4` были выключены, запущены
> `virsh -c qemu:///system start`; hub-VM `192.168.122.123`, registry-контейнер и раннер поднялись сами; (2) токен `gh`
> в gnome-keyring и недоступен, пока keyring заблокирован: PR и `gh workflow run` невозможны, пока владелец не
> разблокирует (`gh auth status` должен снова печатать); (3) на hub-VM нужно ≥8 ГиБ свободного места
> (`docker builder prune -af`), а сборку образов лучше прогреть вручную (`docker build --builder default ...`),
> иначе harness падает «local image command failed».
>
> **GitHub (настроено в третьей сессии по разрешению владельца):** окружение `kornode-e2e` (required reviewer —
> владелец, только protected-ветки), секреты окружения `E2E_SSH_KEY`/`E2E_SSH_KNOWN_HOSTS` (отдельный ключ из
> `~/.e2e` на hub-VM, не личный), переменные `E2E_*_HOST`, `E2E_SSH_USER/PORT`, `E2E_PREVIOUS_*_IMAGE`,
> `E2E_ENVIRONMENT_APPROVAL_CONFIGURED=true`; self-hosted runner `kornode-e2e-hub` (метка `kornode-e2e`, сервис
> systemd на hub-VM; **в момент записи показывал `offline`** — раннер подключился, но брокер GitHub из VM отвечает
> медленно; проверить `gh api repos/r4ven-me/kornode/actions/runners`); `main` защищена от force-push/удаления.

Вставь всё ниже черты в новую сессию Claude Code в
`/home/lans/Cloud/Projects/public/kornode`. Начни в режиме плана.

---

Продолжаем редизайн kornode (hub+agents, один reconciler). Язык — русский, обращайся ко мне «Ivan».
Прочитай по порядку: `CLAUDE.md`, `AGENTS.md`, `docs/redesign/ROADMAP.md` (фаза P4), раздел «Дальнейшие
действия» в `docs/redesign/PLAN.ru.md`, `docs/redesign/DECISIONS.md` (D-55…D-67), `docs/spec/07-fabric.md`,
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
- **P4-03** (D-66): записи зоны в реестре (`korctl dns record add/del/list [--node]`, `/api/dns/records`,
  панель Agents → Fabric DNS), хаб отвечает за всю зону (`local=` + `host-record`/`cname`, рестарт dnsmasq
  только при изменении и только если он под supervisor), секция `dns` в пакете (своя зона + форвард на
  `internal_dns.listen`), dnsmasq агента (supervisor, `autostart=false`, асинхронно с повторами,
  `bind-dynamic`, форвард с `@<fabric_address>` — иначе RPF хаба режет запрос), адрес резолвера на `lo`
  ставит `kornode.net` (`NodeFacts.local_addresses`). Harness: `dns_record`, `dns_resolve`.
- **P4-04** (D-67): слушатель агента (`korctl agent access`, `/api/agents/{name}/access`, панель), серверный
  сертификат от CA центра **без OU** (ключ шифруется мастер-ключом и запечатывается на агента), секция `access`
  в пакете (хэши ocpasswd, строгая валидация), `kornode_agent.access` + общий `programs.Converger`, ocserv как
  supervisor-программа в `/run/kornode-access` (каталог данных агента 0700 недоступен воркерам ocserv), строгий RPF
  на `vpns*` (`NodeFacts.access_ifaces`). E2E-ловушки: контейнеры агентов E2E **не в host-сети** (порт 8443
  публикуется у agent-a, 9100 — у хаба в кейсе `routed`); VPN-клиент agent-b живёт в отдельном compose-сервисе
  `client`, иначе его внешний TLS попадает под политику `kornode.net` агента-b.
- **P4-05** (D-68, источники агентов): doctor `foreign_nat_on_source` (nft + legacy iptables, читается только при уже загруженной таблице `nat`), один `missing_source`, `docs/sources.md`, E2E NL-06 (docker-сеть `source` 10.8.3.0/24 между контейнерами `node` и `client` agent-b: клиент ↔ хаб ↔ agent-a без NAT). Источники хаба и NL-05 не сделаны.
- Остаётся 7 skip в `tests/e2e/test_routed_fabric.py`: E2E-07, NL-05, NL-07…NL-09, NL-13-forwarding,
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
2. **P4-06 … P4-07** (`ROADMAP.md`, `docs/spec/07-fabric.md`; P4-03…P4-05 сделаны): источники хаба (их отложили сюда в D-68: у хаба нет модели egress),
   (wg-easy/Amnezia), `via: exit:<node>`, панель/CLI/API фабрики. Каждая задача: spec → тесты → код →
   docs → `make check` → netlab → (E2E там, где задача трогает data plane); `parity.yaml` обновляется в той же
   задаче. Каждому E2E-кейсу из списка skip нужен реальный сценарий, не заглушка.
3. **E2E-04** в цикле из 5 прогонов (2026-10-20) — 5 passed, плавающий сбой не воспроизведён. Если появится снова,
   снять `audit.jsonl` хаба по ходу прогона (подозрение: `reload ocserv` / `disconnect` сразу после старта хаба).
4. **E2E-06 (обновление)** работает: предыдущие образы — сборка из слияния PR #1, лежат в registry-контейнере на
   hub-VM (`192.168.122.123:5000`, insecure-registry прописан на всех четырёх VM). Digest'ы — переменные репозитория
   `E2E_PREVIOUS_*_IMAGE` и `~/.e2e/env.sh` на hub. Когда образы устареют (несовместимый контракт), собрать новые так же.
5. **Прогон `e2e.yml` на GitHub Actions**: всё настроено (см. блок «GitHub» вверху), нужно **запустить**
   `gh workflow run e2e.yml --ref main -f confirmation=DISPOSABLE_VMS` и одобрить деплой (required reviewer —
   владелец; если одобрение невозможно из CLI — попросить владельца). Предварительно убедиться, что раннер `online`.
   Если раннер остаётся `offline`, смотреть `~/actions-runner/_diag/` на hub-VM (брокер GitHub из VM отвечает медленно).
6. Обновлять `PLAN.ru.md`, `ROADMAP.md`, `CHANGELOG.md` и этот файл вместе с изменениями; отчёт — по формату
   из `CLAUDE.md` (что изменилось, ID задач, доказательства тестами, записи в `DECISIONS.md`).

## Что нужно от меня (напомни заранее)
Одобрение деплоя окружения `kornode-e2e` для первого прогона `e2e.yml`; решение, нужен ли `E2E_HUB_ADDRESS`
(сейчас используется адрес hub-VM). Push и слияние PR по задачам P4 мне разрешены (2026-10-20) — после зелёного CI.

## Правила
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make check` → netlab. Тесты не ослаблять; если
тест кодирует убираемое поведение — удалить/обновить в том же PR и сказать об этом. Значимые изменения —
локальным коммитом, `--no-verify` не использовать. Ядро трогает только `kornode.net`.
