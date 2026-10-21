# Prompt for the next session — P4-07, остаток P4-06, P5-05, `e2e.yml`

> **Состояние на 2026-10-21 (пятая сессия).** В `main` влита ветка `redesign/p4-06b-hub-egress` (`95b0b62`, три
> среза + удаление v1): модель egress хаба (**D-72**), `HubEgressService` (`korctl egress|source`, `/api/egress`,
> `/api/sources`, панель Network → Egress and sources, parity), источники хаба, выход хаба через `exit:<n>`, и
> **удаление всего v1-маршрутизации одним блоком (D-73, P5-03)** — `config/legacy.py`, `RoutingService`,
> `external_lists`, `upstream_pushed`, ключи `routing.client_policy|host_policy|split|host_split|fwmark|table_id`,
> per-profile маршруты/host-маршруты/pushed-маршруты, `korctl routes|upstream hook|sync`, вкладка Routing панели.
> `examples/` и `config.example.yaml` — формат v2 (`tests/test_examples.py`). **CI на `main` (`95b0b62`) зелёный:
> backend, frontend, netlab.** Слияние — локально `git merge --no-ff` + `git push origin main` (`gh` не работает).
>
> Доказательства: `make lint typecheck test render parity` на Python 3.13 и 3.12 — 1150 passed / 92 skipped;
> фронтенд 32 теста + сборка; netlab на hub-VM 69 passed (golden `hub_egress_exit` загружается в ядро). E2E `routed` на
> четырёх VM после этих изменений (harness переведён на `egress: []`): 6 passed, 7 skipped — как до них.
>
> **Не сделано:** P4-07 (раздел Fabric: топология/префиксы/DNS/источники в одном месте), set/domain-выходы через
> `exit:<n>` (нужны одинаковые наборы на хабе и узле), NL-05, NL-07…NL-09, NL-17/NL-18, E2E-07 в редакции спеки,
> упорядоченный редактор правил с drag и inline-explain (P5-01, сейчас JSON), URL-источники `sets` на хабе
> (`route_urls`/`domain_urls` отвергаются как `runtime_unsupported`), README / `docs/architecture.md` /
> `docs/networking.md` (всё ещё про v1, P5-05), прогон `e2e.yml` на GitHub Actions, пересборка образов E2E-06
> (флаг-день D-71 и новая конфигурация).
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
действия» в `docs/redesign/PLAN.ru.md`, `docs/redesign/DECISIONS.md` (D-55…D-71, S-07), `docs/spec/07-fabric.md`,
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
- **S-07 / D-71 + удаление `fabric.enabled`** (четвёртая сессия): ocserv хаба имеет два хоста на одном 443/tcp,
  выбор по TLS SNI. **Хост клиентов** (по умолчанию) сохраняет все методы входа из `auth.*` (пароль, сертификат,
  OIDC, OTP); ограничение D-43 снято. **Vhost** `[vhost:fabric.<fabric.domain>]` (`FabricConfig.server_name`) —
  агенты и enroll: свой сертификат `certs/fabric.crt` (CA хаба, SAN = имя, ключ сохраняется при перевыпуске →
  стабильный pin; `CertificateService.ensure_fabric_certificate`, вызывается в `initialize_runtime`), `ca-cert` = CA
  хаба, `crl`, `auth = plain[passwd=ocpasswd-enroll]` + `enable-auth = certificate`, `cert-user-oid 2.5.4.3`,
  `cert-group-oid 2.5.4.11`, **`udp-port` повторяется в секции** (иначе нет DTLS), секция — последняя в файле. Guard
  connect-script по `$VHOST` (`renderers/ocserv.py`): на vhost пускает только `agents`/`agent-<id>` из реестра и
  `enroll`/`enroll-*`; на хосте клиентов не пускает в эти группы, пустая группа (OIDC) — норма. Enroll-аккаунты пишутся
  в `secrets/ocpasswd-enroll` (`UserService.create_enroll_user`). Контракт: токен `sni`, пакет `hubs[].server_name`
  (схема `bundle.v1.schema.json`), `HubConfig.server_name`, `DialSpec.server_name` → `--resolve=<имя>:<адрес хаба>
  <имя>:<порт>`; `pin` в токене и пакете — pin `fabric.crt`. **`fabric.enabled` удалён** (ключ отвергается как
  неизвестный): реестр, группы, enroll guard, DNS-зона фабрики (при `server.enabled`), программа
  `registry-snapshot` — всегда; адреса выводятся всегда (пул клиентов `10.100.<id>.0/24` вместо `10.10.10.0/24`,
  при явном `server.ipv4_network` `internal_dns.listen` следует за ним; `derive_fabric_defaults` больше не проверяет
  DNS — это делает общий валидатор). API/панель: из Fabric settings убран переключатель, из ответов
  `/api/control/status`, списков агентов и DNS — поля `enabled`/`fabric_enabled`. Найденные по дороге ошибки:
  `GET /api/groups` падал на файле группы `agents` (теперь `RESERVED_GROUPS` пропускаются), `initialize_runtime`
  не создавал CRL, нужный ocserv. Тесты нефабричного режима удалены (список — в CHANGELOG). Решение — D-71 в
  `DECISIONS.md`, спека — `07-fabric.md`, `05-control-plane.md`, `01-addressing.md`, `10-migration.md`.
- **P4-06 часть 1** (D-69, влита в `main`): `via: exit:<n>` для трафика агентов (`to: any`,
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
  **Перед пушем в `main` гонять все шаги CI backend:** `make lint typecheck test render parity PYTHON=.venv/bin/python`
  (`make check` не включает `render` и `parity`; `typecheck` ещё проверяет `tests/e2e`). CI использует Python 3.12:
  `uv venv --python 3.12 /tmp/v312 && VIRTUAL_ENV=/tmp/v312 uv pip install -e '.[dev]'`. Список шагов упавшего
  джоба читается без токена: `GET https://api.github.com/repos/r4ven-me/kornode/actions/runs/<run>/jobs`.
- Фронтенд: системный npm 9.2 падает на `vite` 8 (`edgesOut`); обновлять lock через `npx -y npm@11 update <пакет>`.
- Shell пользователя — zsh: переменные с аргументами `ssh` не разбиваются. Используй функцию
  `vm() { ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 lans@192.168.122.123 "$@"; }`.
- `gh` (аккаунт `r4ven-me`) сейчас **не работает** (заблокирован keyring, см. начало файла); `git push` по SSH работает.
  Push, слияние PR и запуск workflow владелец разрешил для задач редизайна (2026-10-20) — после зелёного CI и без обхода проверок.
- **Одноразовые VM:** hub `192.168.122.123`, agent-a `.211`, agent-b `.26`, ext `.202`. SSH: пользователь
  `lans`, ключ `~/.ssh/id_ed25519`, `-o IdentitiesOnly=yes`, passwordless sudo. Синхронизация дерева на hub:
  `rsync -a --delete` с исключением `/artifacts`, `.git`, `.venv`, `node_modules` в `~/kornode/`.
  Старый netlab-стенд `.30` недоступен; **netlab гоняется на hub-VM** (там поставлены `ocserv openconnect
  nftables gnutls-bin`, есть `tcpdump iproute2`): `sudo -n .venv/bin/python -m pytest -m netlab -q`
  из `~/kornode` (полный набор ≈ 7 мин, 68 passed). В фоне: `(nohup sudo -n ... > /var/tmp/x.out 2>&1 < /dev/null &)`.
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
   guard по `$VHOST`, токен `sni`, пакет `hubs[].server_name`; `fabric.enabled` удалён и влит в `main`.
2a. ~~P4-06 часть 2 + P5-03~~ — сделано (D-72, D-73). Остаток: доменные/set-выходы агентов и хаба, NL-17/NL-18 (netlab),
   E2E-07 по спеке, NL-05, прогон E2E `routed` на четырёх VM.
3. **P4-07**: панель/CLI/API фабрики (топология, префиксы узлов, записи DNS — сейчас они на странице Agents →
   Fabric DNS —, источники), parity. Раздел `Fabric` в панели.
4. **Прогон `e2e.yml` на GitHub Actions**: настроено (см. начало файла). Нужно, чтобы владелец разблокировал keyring, затем
   `gh workflow run e2e.yml --ref main -f confirmation=DISPOSABLE_VMS` и одобрение деплоя (required reviewer — владелец).
   Раннер должен быть `online`; иначе смотреть `~/actions-runner/_diag/` на hub-VM.
5. **Пересобрать базу E2E-06 (флаг-день D-71):** образы «предыдущей версии» в registry-контейнере на hub-VM собраны до
   vhost'ов и теперь несовместимы; собрать новые из текущего `main` тем же способом, что при слиянии PR #1, и обновить
   `E2E_PREVIOUS_HUB_IMAGE`/`E2E_PREVIOUS_AGENT_IMAGE` (без работающего `gh` — только владелец).
6. Известные нерешённые мелочи: нестабильный по таймауту `test_suppress_rule_keeps_connected_routes_ahead_of_policy_table`
   (netlab, HTTP 2 с; при повторе в одиночку проходит — если повторится в CI, поднять таймаут); E2E NL-04 один раз упал в полном прогоне (дамп маршрутов был полным, в одиночку и в
   повторе проходит); E2E-04 в цикле из 5 прогонов — 5 passed (если вернётся, снять `audit.jsonl` хаба по ходу
   прогона); сертификат слушателя access живёт 825 дней, обновление — `korctl agent access set <имя> --hostname H
   --reissue`, doctor хаба предупреждает за 30 дней; первый apply после рестарта *процесса* агента перезапускает ocserv
   (принято, D-67); E2E-06 использует образы из слияния PR #1 (registry-контейнер на hub-VM) — когда контракт пакета
   изменится несовместимо, собрать новые так же.
7. Обновлять `PLAN.ru.md`, `ROADMAP.md`, `CHANGELOG.md` и этот файл вместе с изменениями; отчёт — по формату
   из `CLAUDE.md` (что изменилось, ID задач, доказательства тестами, записи в `DECISIONS.md`).

## Что нужно от меня (напомни заранее)
Разблокировать gnome-keyring (чтобы `gh` снова работал: PR, `gh workflow run`), одобрить деплой окружения
`kornode-e2e` для первого прогона `e2e.yml`; решить, нужен ли `E2E_HUB_ADDRESS` (сейчас — адрес hub-VM); обновить `E2E_PREVIOUS_*_IMAGE` после пересборки базы E2E-06. Push и слияние
по задачам P4 мне разрешены (2026-10-20) — после зелёных проверок.

## Правила
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make lint typecheck test render parity` → netlab. Тесты не ослаблять; если
тест кодирует убираемое поведение — удалить/обновить в том же PR и сказать об этом. Значимые изменения —
локальным коммитом, `--no-verify` не использовать. Ядро трогает только `kornode.net`.
