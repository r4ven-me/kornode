# Prompt for the next session — P4-06 часть 2 + P5-03, P4-07, `e2e.yml`

> **Состояние на 2026-10-21 (конец четвёртой сессии).** В `main` влиты PR #1…#3, P4-05, P4-06 часть 1,
> фикс CI (`vite` 8.3.x) и **S-07 / D-71** (vhost фабрики по SNI, `main` = `999b06b`, CI зелёный: backend, frontend,
> netlab). **Удаление `fabric.enabled`** лежит на ветке `redesign/p4-fabric-always-on` (коммит `b5a17e8` + правка
> CRL): хаб всегда запускает фабрику, адреса всегда выводятся (пул клиентов `10.100.<id>.0/24`), ключ `fabric.enabled`
> отвергается как неизвестный. Слияние локальным `git merge --no-ff`/fast-forward + `git push origin main` (CI на `main`
> идёт по push; `gh` не работает, см. память `gh-keyring-blocks-cli`).
>
> Доказательства: S-07 — netlab `test_spike_p4_vhosts.py` 12 passed (ocserv 1.3.0), `make check` 1227 passed / 91
> skipped, netlab на hub-VM 68 passed (A) и 67 passed + 1 флак `test_suppress_rule_…` (B; отдельно 2/2 passed), E2E
> `routed` (A): 6 passed, 7 skipped. **Флаг-день D-71:** хаб и агенты обновляются вместе; образы базы для E2E-06 надо
> пересобрать из слияния этой ветки (как при любом несовместимом контракте пакета).
>
> **Не сделано:** P4-06 часть 2 вместе с P5-03 (модель egress хаба, удаление legacy-ключей), P4-07 (раздел Fabric в
> панели/CLI/API), NL-05, NL-07…NL-09, прогон `e2e.yml` на GitHub Actions, `examples/` и README в формате v2 (P5-05;
> они ещё используют явный пул `10.10.10.0/24`, это валидно).
>
> **Важно для продолжения:**
> 1. Хост перезагружался: VM `debian13-kornode1..4` были выключены, их запускают `virsh -c qemu:///system start
>    <имя>`; после этого hub-VM `192.168.122.123`, registry-контейнер и раннер поднимаются сами.
> 2. `gh` зависает без вывода, пока gnome-keyring заблокирован. До разблокировки: `git push` по SSH работает,
>    статус CI читается через публичный API (`curl https://api.github.com/repos/r4ven-me/kornode/commits/<sha>/check-runs`),
>    слияние — локальным `git merge --no-ff` + `git push origin main` (CI на `main` идёт по push). Создать PR или
>    запустить `gh workflow run e2e.yml` может только владелец, разблокировав keyring (`gh auth status` должен снова печатать).
> 3. На hub-VM нужно ≥8 ГиБ свободного места (preflight harness): `docker builder prune -af`. Перед E2E прогрей
>    образы вручную (`docker build --builder default --file Dockerfile[.agent] .`, с повторами): иначе harness
>    падает «local image command failed» из-за нестабильного PyPI.
> 4. Контейнеры агентов в E2E **не в host-сети**, а в docker-сети VM; порты публикует только harness (8443 у agent-a,
>    9100 у хаба и ext в кейсе `routed`). Адрес хаба — «carrier» туннеля агента: политика на него не действует
>    (D-20), поэтому он не годится как «интернет» в тестах выхода. Адрес VPN-сервера тоже: у клиента к нему
>    host-маршрут мимо туннеля. «Интернетом» служит контейнер `ext` (`192.168.122.202:9100`).
>
> **GitHub (настроено по разрешению владельца 2026-10-20):** окружение `kornode-e2e` (required reviewer —
> владелец, только protected-ветки), секреты окружения `E2E_SSH_KEY`/`E2E_SSH_KNOWN_HOSTS` (отдельный ключ из
> `~/.e2e` на hub-VM, не личный), переменные `E2E_*_HOST`, `E2E_SSH_USER/PORT`, `E2E_PREVIOUS_*_IMAGE`,
> `E2E_ENVIRONMENT_APPROVAL_CONFIGURED=true`; self-hosted runner `kornode-e2e-hub` (метка `kornode-e2e`, сервис
> systemd на hub-VM) — **последний раз показывал `offline`**: он подключается, но брокер GitHub из VM отвечает
> медленно (проверить `gh api repos/r4ven-me/kornode/actions/runners`, логи — `~/actions-runner/_diag/`); `main`
> защищена от force-push и удаления.

Вставь всё ниже черты в новую сессию Claude Code в
`/home/lans/Cloud/Projects/public/kornode`. Начни в режиме плана.

---

Продолжаем редизайн kornode (hub+agents, один reconciler). Язык — русский, обращайся ко мне «Ivan».
Прочитай по порядку: `CLAUDE.md`, `AGENTS.md`, `docs/redesign/ROADMAP.md` (фаза P4), раздел «Дальнейшие
действия» в `docs/redesign/PLAN.ru.md`, `docs/redesign/DECISIONS.md` (D-55…D-70, S-07), `docs/spec/07-fabric.md`,
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
- **P4-06 часть 1** (D-69, ветка `redesign/p4-06-exit-via-node`): `via: exit:<n>` для трафика агентов (`to: any`,
  `from` clients/sources, источник экспортирован; `host` и set/доменные назначения запрещены валидатором).
  Хаб выводит транзитные выходы из политик агентов в реестре (`HubNetInputs._transit_exits`), метит пакеты по
  **префиксу источника** (именованный набор `transit<n>_v4`, скрипт не зависит от подключений) в таблицу узла n
  (`default dev <vpnsX узла n>` + `unreachable`, пока узел офлайн), ответы от узла n пропускают строгий RPF
  (`transit_ifaces`), без NAT на хабе. **Новое: хаб режет трафик агентов к не-фабричным назначениям**, если ни одна
  политика не объявила выход (`fabric_guard`; раньше такой трафик уходил без метки и без NAT). Узел-выход (роль `exit`):
  неявное правило `from fabric → any via local` + маскарад; ответы из интернета возвращаются через **маршруты
  префиксов фабрики в `main` (proto 77)**, которые агент ставит, если в его политике есть правило `from: fabric`
  (`AgentNetInputs`: `session_routes`). Перемаркировка ответов не работает (см. D-69: `src_valid_mark=1`).
  Валидация: цель — другой активный агент с ролью `exit`, роль нельзя снять, пока на узел ссылаются
  (`exit_in_use`), компилятор пакета перепроверяет цель. Тесты: `tests/test_net_transit.py`, `tests/test_agent_exit.py`,
  golden `hub_transit`/`agent_exit`/`exit_node` (загружаются в ядро в netlab). Harness: `exit_role`,
  `access_policy(via=...)`, `fleet.tcp_unreachable`, `ext` публикует 9100.
- Остаются skip в `tests/e2e/test_routed_fabric.py`: E2E-07 (в редакции спецификации — хаб-источник и доменные
  выходы, часть 2; реальный сценарий выхода агентов называется `test_e2e_07_client_of_agent_a_...` и проходит),
  NL-05, NL-07…NL-09, NL-13-forwarding, E2E-06-clients (причины — в самом файле).

## Окружение
- Используй `.venv`: `.venv/bin/python -m pytest`, `.venv/bin/python -m mypy --strict backend`,
  `.venv/bin/python -m ruff check backend tests` (не `ruff format` по всему репо). Системный python не годится.
- Shell пользователя — zsh: переменные с аргументами `ssh` не разбиваются. Используй функцию
  `vm() { ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 lans@192.168.122.123 "$@"; }`.
- `gh` (аккаунт `r4ven-me`) сейчас **не работает** (заблокирован keyring, см. начало файла); `git push` по SSH работает.
  Push, слияние PR и запуск workflow владелец разрешил для задач редизайна (2026-10-20) — после зелёного CI и без обхода проверок.
- **Одноразовые VM:** hub `192.168.122.123`, agent-a `.211`, agent-b `.26`, ext `.202`. SSH: пользователь
  `lans`, ключ `~/.ssh/id_ed25519`, `-o IdentitiesOnly=yes`, passwordless sudo. Синхронизация дерева на hub:
  `rsync -a --delete` с исключением `/artifacts`, `.git`, `.venv`, `node_modules` в `~/kornode/`.
  Старый netlab-стенд `.30` недоступен; **netlab гоняется на hub-VM** (там поставлены `ocserv openconnect
  nftables gnutls-bin`, есть `tcpdump iproute2`): `sudo -n .venv/bin/python -m pytest -m netlab -q`
  из `~/kornode` (полный набор ≈ 6,5 мин, 55 passed).
- **E2E на hub:** `. ~/.e2e/env.sh; export TMPDIR=/var/tmp`, затем `.venv/bin/python -m tests.e2e preflight`
  и `.venv/bin/python -m pytest tests/e2e/test_routed_fabric.py --e2e-run -q --tb=short` (кейс `routed` целиком ≈ 25 мин, один сценарий 3–9 мин). Запускай в фоне (`nohup ... > /var/tmp/x.out`) и жди по `grep` в файле вывода,
  а не по `pgrep -f` (он находит собственную команду). После падения:
  `python -m tests.e2e cleanup --all-owned --yes`.
- Сборка образа на VM после смены исходников требует рабочего PyPI и иногда падает «local image command
  failed» за ~20 с; помогает повторить (слои в кэше) или собрать `docker build --builder default --file
  Dockerfile[.agent] .` вручную на hub.
- Вывод harness намеренно скрыт (`output withheld`). Для разбора сетевых падений используй `net_dump`.

## Что делать дальше (по порядку)
1. ~~Проверить CI на `main`~~ — сделано (vite 8.3.x, `main` зелёный).
2. ~~Spike S-07~~ — сделано (D-71): vhost `fabric.<fabric.domain>`, отдельный сертификат `fabric.crt`, `ocpasswd-enroll`,
   guard по `$VHOST`, токен `sni`, пакет `hubs[].server_name`; `fabric.enabled` удалён (ветка выше, влить после зелёного E2E).
2a. **P4-06 часть 2 вместе с P5-03** (D-69, D-70): модель egress хаба. Ключи `egress`/`sources`/`sets` в `config/models.py`
   **заменяют** старые ключи — `legacy_policy` и `kornode.config.legacy` удаляются, тесты v1-поведения тоже (списком в PR), валидация против ролей реестра, parity-поверхности
   `egress.hub`/`sources.hub` (CLI `egress show/edit/set/check`, `GET/PUT /api/egress`, `source add/del/list`,
   панель Network → Egress/Sources, строки в `parity.yaml`), источники хаба в `HubNetInputs.facts()` (`SourceFact`,
   их подсеть в `node_prefixes[1]`, экспорт агентам через пакет и per-user `route`), выход хаба через `exit:<n>`
   (клиенты хаба, источники хаба, хост хаба): таблица узла n уже есть, нужны метки по классам хаба и **обратный маршрут
   на узле n** для источников с `export: false`. Затем: доменные/set-выходы агентов (нужны одинаковые наборы на хабе),
   NL-17/NL-18 (netlab), E2E-07 в редакции спецификации, NL-05. Источники хаба и их doctor-проверки отложены сюда из D-68.
   **Карта legacy-ключей (снята 2026-10-21, grep по `backend frontend tests docs/spec parity.yaml`):** ключи
   `client_policy`/`host_policy`/`host_split`/`legacy_policy`/`routing.split`/`fwmark`/`table_id` живут в
   `config/models.py` (RoutingConfig и миграции), `config/legacy.py` (175 строк, удаляется целиком),
   `config/defaults.py`, `services/routing.py` (550 строк), `services/netinputs.py` (`legacy_policy`),
   `services/upstream.py`, `services/host_dns.py`, `services/backup_state.py`, `services/apply.py`,
   `renderers/dnsmasq.py` (split-домены), `api/routes_routing.py`, `api/routes_upstream.py`,
   `tunnels/vpnc-script-kornode`; фронтенд — `lib/drafts.ts`, `app/hooks/useRouting.ts`, `api.ts`,
   `views/upstream/*` (RoutingListSourcesPanel, профили). Тесты v1: `test_config_legacy.py`,
   `test_routing_policy_migration.py`, `test_routing_api.py`, `test_routing_service.py`, `test_domain_resolver.py`,
   `test_dnsmasq_render.py`, часть `test_upstream_*`, `test_net_service.py`, `test_netinputs.py`, netlab
   `test_p0_upstream.py`/`kornode_nodes.py`/`tests/golden/hub.rules`. Общая инфраструктура, которая **остаётся**:
   `net/` (kernel, compile, diff, state: `fwmark`/таблицы выходов как внутренняя деталь компилятора), reconciler,
   kill switch. Делать вертикальными срезами: модель `egress`/`sources`/`sets` + валидатор → компилятор хаба поверх
   `kornode.net` → CLI/API/панель + parity → удаление legacy одним блоком → netlab NL-17/NL-18.
   Перед пушем в `main` гонять **все** шаги CI: `make lint typecheck test render parity` (память
   `ci-steps-beyond-make-check`), иначе красный `main` из-за `config.example.yaml` повторится.
3. **P4-07**: панель/CLI/API фабрики (топология, префиксы узлов, записи DNS — сейчас они на странице Agents →
   Fabric DNS —, источники), parity. Раздел `Fabric` в панели.
4. **Прогон `e2e.yml` на GitHub Actions**: настроено (см. начало файла). Нужно, чтобы владелец разблокировал keyring, затем
   `gh workflow run e2e.yml --ref main -f confirmation=DISPOSABLE_VMS` и одобрение деплоя (required reviewer — владелец).
   Раннер должен быть `online`; иначе смотреть `~/actions-runner/_diag/` на hub-VM.
5. Известные нерешённые мелочи: E2E NL-04 один раз упал в полном прогоне (дамп маршрутов был полным, в одиночку и в
   повторе проходит); E2E-04 в цикле из 5 прогонов — 5 passed (если вернётся, снять `audit.jsonl` хаба по ходу
   прогона); сертификат слушателя access живёт 825 дней, обновление — `korctl agent access set <имя> --hostname H
   --reissue`, doctor хаба предупреждает за 30 дней; первый apply после рестарта *процесса* агента перезапускает ocserv
   (принято, D-67); E2E-06 использует образы из слияния PR #1 (registry-контейнер на hub-VM) — когда контракт пакета
   изменится несовместимо, собрать новые так же.
6. Обновлять `PLAN.ru.md`, `ROADMAP.md`, `CHANGELOG.md` и этот файл вместе с изменениями; отчёт — по формату
   из `CLAUDE.md` (что изменилось, ID задач, доказательства тестами, записи в `DECISIONS.md`).

## Что нужно от меня (напомни заранее)
Разблокировать gnome-keyring (чтобы `gh` снова работал: PR, `gh workflow run`), одобрить деплой окружения
`kornode-e2e` для первого прогона `e2e.yml`; решить, нужен ли `E2E_HUB_ADDRESS` (сейчас — адрес hub-VM). Push и слияние
по задачам P4 мне разрешены (2026-10-20) — после зелёных проверок.

## Правила
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make check` → netlab. Тесты не ослаблять; если
тест кодирует убираемое поведение — удалить/обновить в том же PR и сказать об этом. Значимые изменения —
локальным коммитом, `--no-verify` не использовать. Ядро трогает только `kornode.net`.
