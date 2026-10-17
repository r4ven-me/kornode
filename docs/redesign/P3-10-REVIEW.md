# P3-10 — передача основному Claude на ревью

Дата: **2026-10-17**. **Harness реализован, задача НЕ принята и НЕ Done.**
Владелец прямо разрешил реализацию до ревью P3-07/P3-08/P3-09; их приёмка этим
не подменяется. Работал один implementer, без субагентов. Ветка по-прежнему
`redesign/p3-08-agent-management`; весь стек P3-07…P3-10 незакоммичен, включая
untracked files. Коммитов/новых веток/merge/push не было. Накопительная передача
[CLAUDE-HANDOFF.md](CLAUDE-HANDOFF.md) дополнена, предыдущие REVIEW сохранены.

## Реализовано

- `tests/e2e/inventory.py`: env-only inventory четырёх разных IPv4 VM, отдельный
  SSH account/key, host pins, exact destructive ACK, paired immutable previous
  image refs. Inventory/hosts не выводятся через repr.
- `transport.py`: OpenSSH без наследования config, password fallback, forwarding
  или TOFU; strict known_hosts. Неизбежный remote login shell получает только
  `shlex.join`-quoted fixed Python worker; JSON/secrets — stdin. Ответы ограничены,
  raw output/exception repr скрыты. Image transfer ≤3 GiB через private temp files,
  не GB-sized RAM buffers. Нет `shell=True`.
- `worker.py`: standalone stdlib Python на VM, application imports только в образах.
  Каждое действие проверяет root-owned `/etc/kornode-e2e-vm.json` (purpose, role,
  actual machine ID). Exclusive lease, 24-hex run ID, allowlisted actions/cases,
  отсутствие stale-lease stealing и generic exec/upload/delete endpoint.
- `fleet.py`: четыре разные machine identity и runner именно на hub; lease всех
  VM → build обоих образов один раз → save/load → fresh per-case Compose.
  Docker commands привязаны к `unix:///var/run/docker.sock`, builder `default`.
- Workload — **bridge/container netns**, NET_ADMIN/NET_RAW/TUN, без privileged,
  host PID/network или Docker socket. Metadata/config/Compose root bind **RO**,
  только state/recovery RW. Workload не может переписать cleanup Compose через
  доступный ему writable case root.
- Detached watchdog вооружается до fault и удаляет только `kn_e2e_fault` внутри
  исходного immutable container ID. Никакой blackhole хостового SSH/firewall.
- Fixture `finally`: sanitized agent diagnostics + teardown даже при partial setup;
  artifact disk error не препятствует попытке cleanup всех VM. Private atomic
  `active.json` recovery ledger и summary outcomes/metrics/blockers. Explicit
  recovery сохраняет marker/lease checks и отказывается от чужого run.
- `conftest.py`: default skip всех VM tests даже от root; opt-in switch + ACK,
  запрет showlocals/xdist, upgrade skip при отсутствии baseline.
- `__main__.py`, Makefile: offline `make e2e-plan`, explicit preflight, `make e2e`,
  owned-run recovery. `make typecheck` теперь включает strict harness mypy.
- `.github/workflows/e2e.yml`: manual confirmation либо same-repo PR label `e2e`,
  protected Environment, singleton concurrency без cancel, timeout 90 min;
  no `pull_request_target`, checkout credentials не сохраняются. Temp private
  SSH files, local tests до remote access, always recovery / narrow upload /
  key removal. Реальную environment protection обязан настроить владелец.
- `tests/test_e2e_harness.py`: **49 локальных safety-тестов** (mocked VM/Docker,
  не E2E evidence): inventory, pins, stdin, markers/leases/ownership, isolation/RO,
  cleanup/setup/artifact failures, watchdog ordering, signed/tampered injection
  на локальном registry, SLA deadlines, compile embedded scripts, workflow trust /
  upload allowlist, offline plan, local Docker socket/default builder.
- D-58 (**implementation choice pending review**), spec 09, roadmap, README,
  changelog и [операционный runbook](../runbooks/vm-e2e.md). Новых dependencies,
  `AppConfig`/GUI fields или application capabilities/parity exemptions нет.

## Сценарии: код есть, VM-запуска не было

| ID | Что фактически проверяет opt-in тест |
| --- | --- |
| E2E-01 | real create/enroll → mTLS fabric ≤30 s для обоих агентов; initial confirmed bundle |
| E2E-02 | registry transport mutation → confirmed applied version ≤10 s |
| E2E-03 | agent-b container uplink fault/watchdog, auto fabric recovery |
| E2E-04 | revoke → fabric недоступна + реальный mTLS HTTP 403 через test-only relay |
| E2E-05 | rotation announcement → backup → advance version → stopped owned data wipe → staged restore/activation → прежние certs и monotonic high-water recovery |
| E2E-06 | fresh compatible previous images → current hub/agents, continuous fabric mTLS probes, max good-probe gap ≤30 s; certificate identity сохранена |
| NL-10 | owned route удаляется через `kornode.net.Kernel` в agent netns; running reconciler восстанавливает ≤2 s |
| NL-11 | test-only validly signed bundle с fabric port 1 → rollback ≤70 s и hub report |
| NL-12 | реально изменённые после подписи bytes → signature-rejection evidence, current/high-water неизменны |
| NL-13, partial | ≥600 s hub outage, agent cache boot, ext ocserv + ICMP packets и reconnect |

Есть **12 явных P4 blockers/skips**: E2E-07, NL-01…09, full client forwarding
NL-13 и client continuity E2E-06. Они не маскируются «зелёными» placeholders;
причины присутствуют в tests, offline plan, summary и runbook.

## Границы, требующие явного решения ревью

1. **Не production host networking.** D-58 уменьшает blast radius: kornode/faults
   меняют container netns, а Docker создаёт обычные host bridge/NAT/published ports.
   Нет snapshot/revert host nft/routes/sysctls; harness их не flush'ит. Реальный
   меж-VM TCP есть, но public agent-b и VM-level NAT ACL agent-a не воспроизведены:
   оба agent container за Docker NAT. Target topology spec 09 не объявлена закрытой.
2. **P4 не реализуется тестовой инфраструктурой.** Existing upstream ICMP/tunnel
   не доказывает клиентский forwarding, fail-closed packet capture, no fabric NAT,
   wg-easy, internal DNS, MSS/MTU/loss или domain-based egress. Upgrade измеряет
   fabric probes, не throughput/непрерывность клиентского трафика.
3. **10 s registry SLA не ослаблен** ради confirmation window. Если runtime не
   укладывается, реальный тест должен упасть; локальный mock не доказывает SLA.
4. Upgrade требует разных paired `@sha256:` образов, совместимых с P3-07+ CLI,
   config/bundle contracts и forward-only DB schema. Baseline из более старого
   неподдерживаемого интерфейса может не стартовать. Нет downgrade текущей DB;
   scenario стартует на свежем previous state. Без baseline upgrade skip честный.
5. Revoke 403 проверяется через отдельный **test-only** TCP 18444 relay к fabric
   listener. CA/mTLS остаются; только relay probe отключает hostname match из-за
   другого dial address. Это не production control TLS setting. Запрещено
   публиковать relay/Compose в production; ingress ограничить disposable стендом.
6. Backup/passphrase остаются на hub VM. Wipe только после stop owned node, только
   case `data/`; restore в case recovery, activation проверяет config containment,
   явно устанавливает traversal 0711 и пересоздаёт owned container. Production
   `BackupService` остаётся staged-only. Реальные dropped-privilege workers ещё
   требуется проверить; root file reads не acceptance.
7. Protected Environment — внешняя настройка владельца, переменная лишь ACK.
   Label/same-repo guard сами по себе не sandbox: checked-out code на privileged
   self-hosted runner фактически контролирует disposable VM. Нужны required
   reviewers, запрет self-approval, branch restrictions, dedicated/ephemeral runner
   и reimage между trust boundaries. Не включать на production/dev runner.
8. Teardown/recovery best effort, не атомарная DR. Hard kill/SSH/VM failure может
   оставить lease или state; не удалять lease вручную поверх живых workload.
   `cleanup --all-owned --yes` использует private local ledger; при его утрате
   original run ID читается владельцем из VM lease. Чужой lease не красть.
9. Upload только summary, agent-a/agent-b sanitized tar и short JUnit, без raw
   Docker logs/config/backup/keys. Agent diagnostics содержат operational metadata,
   доступ/retention артефактов надо ограничивать. Startup failures без diagnostics
   исследовать локально на disposable VM, не печатать raw secret-bearing output.
10. Большой `worker.py` намеренно standalone stdlib: доставляется одним quoted
    fixed source без host checkout/dependencies. Это privileged test code, требует
    отдельного тщательного ревью boundaries, а не доверия лишь локальным mocks.

## Выполненные локальные проверки

- `.venv/bin/python -m pytest tests/test_e2e_harness.py tests/e2e tests/test_parity.py -q`:
  **53 passed, 22 skipped**, 2.01 s = 49 новых safety + 4 parity; все VM/P4 skips.
- Ruff backend/tests **passed**; strict mypy harness **passed (9 files)**.
- `make e2e-plan` **passed**, `network_actions:false`, inventory/SSH/Docker не читает.
- Полный **`make check`**: ruff **passed**; mypy backend **135 files passed**,
  harness **9 files passed**; pytest **1069 passed, 64 skipped, 2 failed**, 132.30 s.
  **Полный check не зелёный.** Те же прежние `tests/test_enrollment.py`:
  `test_renew_only_after_two_thirds_and_keeps_old_cert` и
  `test_revoke_node_crl_reload_disconnect_and_sync` — fixed clock конфликтует с
  реальной датой certtool; renew возвращает 409. Их/production логику не менял.
- `git diff --check` **passed**; ruff format check **passed** (10 files).
  Quoted fixed SSH worker command — **33,212 bytes**, ниже Linux single-argument
  limit 128 KiB; это только offline size check, не SSH execution.
- Frontend в P3-10 не менялся/не перезапускался. Результаты P3-09 UI сохранены
  в прежней передаче; они не fabric runtime evidence.
- **Не выполнялись:** VM SSH/preflight, Docker build/load/deploy/size, privileged
  netlab, реальная fault injection/restore, CI workflow или Git push.

## Порядок ревью и приёмки

1. Читать накопительную передачу и четыре REVIEW; просмотреть tracked **и untracked**
   дерево, не затереть предыдущую работу. D-55…D-58 и specs 05/06/08/09/11.
2. Ревью implementation P3-07/08/09; затем SSH/worker privileged boundary,
   ownership/RO mounts, fault watchdog, partial setup/teardown/recovery, artifact
   redaction и protected-runner trust P3-10. Принять/изменить D-58 scope явно.
3. На выделенной netlab VM — P3 agent/management/backup scenarios, затем весь
   netlab и прежние P2 prerequisites. Отдельно исправить два clock tests, не
   ослабляя renewal checks; получить зелёный full check до push.
4. Владелец предоставляет четыре disposable VM/полный inventory, root markers,
   pinned SSH, Docker/Compose/Python ≥3.12/TUN, self-hosted hub runner и protected
   Environment; previous images для upgrade. Разрешение на push/run — отдельно.
5. Первый настоящий four-VM run: actual image digests/size, scenario timings/SLA,
   sanitized artifacts и cleanup/recovery evidence. Не считать текущие unit counts
   VM-прохождением; не объявлять полную фазу Done с P4/client/host-network gaps.

Serena MCP в этой сессии не восстановился; использованы обычные file/search/terminal
инструменты. Локальная `.venv` и ignored LSP override — не часть поставки приложения.

## Повторное ревью 2026-10-18

- **Исправлено (MEDIUM):** workflow публиковал `agent-a.tar.gz`/`agent-b.tar.gz` в артефакты публичного
  репозитория (маскирование эвристическое, D-59). Теперь выгружаются только `summary.json` и `junit.xml`;
  архивы остаются на runner-е. Тест `test_e2e_harness.py` и runbook обновлены сознательно.
