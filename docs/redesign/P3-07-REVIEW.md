# P3-07 — передача основному Claude-агенту на ревью

Дата: 2026-10-16. Язык общения с владельцем — русский.

> Ниже сохранён результат P3-07 на момент её завершения. Последующее обновление:
> владелец согласовал P3-08, обе задачи теперь в незакоммиченном рабочем дереве
> `redesign/p3-08-agent-management`. Общая точка входа —
> [Передача Claude](CLAUDE-HANDOFF.md); изменения P3-08 и новые проверки —
> [P3-08-REVIEW.md](P3-08-REVIEW.md). Redactor вынесен из agent inspection
> в общий `kornode.bundle.redaction`, агент импортирует ту же реализацию.
> Утверждения ниже «P3-08 не менялась» и «следующая P3-08» относятся только
> к историческому снимку P3-07, не к текущему дереву.

## Состояние и границы

- Владелец согласовал план P3-07 и создание ветки `redesign/p3-07-agent-cli` от
  `redesign/p3-06-agent`. Изменения **не закоммичены и не запушены**.
- Реализация готова к ревью; задача **не объявлена полностью принятой**:
  привилегированный netlab ещё нужно выполнить. Не реализовывать CLI заново.
- Писал один вспомогательный агент, без субагентов. Финальное ревью и продолжение
  P3 остаются за основным Claude-агентом.
- P3-08/09/10, хабовые CLI/API/GUI, Dockerfile.agent, enrollment-тесты и хвосты
  P2 не менялись. Исключение из пробелов D-54 — doctor, непосредственно входящий
  в P3-07. Новых зависимостей, полей AppConfig и изменений parity.yaml нет:
  локальный CLI агента по spec 08 не является хабовой поверхностью.

## Что реализовано

- `backend/kornode_agent/cli.py`: все команды spec 06 — status, explain, doctor,
  bundle show/history/rollback, diag, reconnect; JSON на любом уровне, exit codes,
  безопасные ошибки без echo входных значений; JSON также у enroll/run/version.
- `backend/kornode_agent/local.py`: строгие RPC-запросы, Unix socket
  `<root>/run/agent.sock`, 0600 **до listen**, bounded frames, таймауты, cleanup;
  flock `<root>/run/agent.lock` до boot и до завершения workers. Второй run и
  enroll/force при работающем процессе отклоняются. Lock inode не удаляется.
- `backend/kornode_agent/agent.py`: `Agent.perform` — общая точка локальных и
  хабовых reconnect/explain/rollback. Rollback идёт через существующий Applier,
  reconnect сериализован с применением. `_worker` дожидается worker при отмене,
  не освобождая apply/process lock раньше времени, и сохраняет CancelledError
  даже при ошибке worker. Report читает атомарный state snapshot с диска.
- `backend/kornode_agent/tunnels.py`: публичный lock-protected snapshot `specs()`
  вместо доступа диагностик к изменяемому `_specs`. Reconnect отозванного агента
  запрещён; неудачный dial не выдаётся за успех.
- `backend/kornode_agent/inspection.py`: верифицированный redacted bundle show,
  локальная история и offline status; фильтрация известных current/cached secrets,
  secret-полей, PEM/tails, sealed objects, auth headers, URL queries. Атомарная
  публикация diag через hard link с no-clobber, 0600, fsync.
- `backend/kornode_agent/doctor.py`: read-only проверки желаемого/фактического
  состояния, sysctl, routes/guards, rules, nft, sources, overlaps, MTU, сертификата;
  findings входят в отчёты и архив. Ошибка проверки не считается успехом.
- `_diag` общий для CLI и collect_diag: rules/routes/nft, report/state/doctor,
  bounded log tails, без symlink logs/ключей/config/raw bundles. RPC передаёт
  base64, CLI пишет архив, а не base64 в stdout. Существующие файлы не затираются.
- Dry-run у rollback и reconnect без записи состояния/изменения сети.
- Документация: spec 06, D-55, changelog, roadmap, указатель из NEXT_SESSION.

## Поведение, которое важно проверить осознанно

1. **Гибридный доступ.** Bundle show/history не требуют процесса/хаба. Status
   сначала использует сокет, при отсутствии listener читает state.json: exit 0,
   running=false, runtime-поля null. Если listener жив, но mTLS ping хаба не
   прошёл — возвращается полезный status и exit 4. Нет listener у runtime-команд
   — exit 1, без второго reconciler. Ошибки permissions/protocol не маскируются
   offline fallback.
2. **Rollback не означает обход health.** Нужен подтверждённый кэш, прежняя
   проверка подписи и health-window. High-water не уменьшается. При недоступном
   хабе локальный откат может не подтвердиться. Таймаут RPC не отменяет уже
   принятое действие и не приводит к автоматическому повтору.
3. **Протокол/порт explain.** Модель egress и общий explain сейчас адресные,
   Kernel.route_get — mark-based. Аргументы валидируются, попадают в query,
   результат содержит явное предупреждение: это не L4-filter/проба соединения.
   Ядро и модель политик ради P3-07 не расширялись.
4. **Doctor не делает недоказанных выводов.** Foreign NAT — консервативное
   предупреждение о чужом NAT с предложением проверить охват owned subnets;
   userspace/kernel versions — информация, а не утверждение совместимости;
   clock skew отмечен unchecked без доверенного времени хаба. Ожидаемая собственная
   подключённая source/access сеть не считается конфликтом сама с собой.
5. **Секреты и ошибки.** Просмотреть маскирование как структурированных полей,
   так и свободного текста логов/ошибок. Фильтр — защита экспорта, не разрешение
   логировать credentials в producers. Известные значения берутся из bootstrap
   camouflage, active и доступных проверенных cached bundles. Исторический
   произвольный unlabelled secret из уже удалённого кэша невозможно распознать
   универсально: producers всё равно не должны писать его в лог.
6. **Lifecycle/конкурентность.** Пройти shutdown при apply/rollback/reconnect,
   клиентском disconnect и ошибке worker; stale socket, owner-only permissions,
   отсутствие unlink regular files/symlinks и отсутствие второго kernel writer.
   Graceful shutdown дожидается текущих workers/потоков; текущий dial может
   задержать завершение, supervisor по-прежнему может применить свой stop timeout.
7. **Совместимость вывода.** Already-enrolled теперь conflict (3), не generic (1);
   human enroll/version имеют labeled output, JSON — стабильный data object.
   Сохранён внутренний restart exit 75 для supervisor.

## Автоматические проверки на этой машине

Окружение: Linux, uid 1000, Python 3.13.5, pytest 8.4.2.

- Базовые существующие store/apply/inputs/tunnels/imports до изменений:
  **30 passed**.
- Новые `tests/test_agent_cli.py`, `test_agent_local.py`, `test_agent_actions.py`,
  `test_agent_doctor.py`: **53 passed**.
- `make check PYTHON=python3` (итоговый прогон):
  - ruff: **passed**;
  - mypy --strict: **passed, 124 source files**;
  - pytest: **948 passed, 40 skipped, 2 failed**, 117.76 s.
- Оба падения — ранее известные, не исправлялись:
  - `tests/test_enrollment.py::test_renew_only_after_two_thirds_and_keeps_old_cert`;
  - `tests/test_enrollment.py::test_revoke_node_crl_reload_disconnect_and_sync`.
  Фиксированные часы теста расходятся с реальным временем certtool;
  EnrollmentService.renew возвращает 409 до вычисленного renewal window.
- `make parity PYTHON=python3`: **4 passed**.
- `python3 -m pytest tests/netlab/test_p3_agent.py -q`: **1 skipped** (не root).
  `ocserv` здесь также не найден. Это **не** успешный privileged netlab.
- `git diff --check`: passed.
- Docker image не собирался, лимит 150 MB не проверялся. На VM/CI ничего не
  запускалось, сеть хоста не перенастраивалась.

## Netlab перед принятием

Расширен существующий `tests/netlab/test_p3_agent.py`:

- live CLI status через настоящий socket и mTLS ping;
- show/history/explain/reconnect dry-run/doctor/diag;
- права сокета и архива, лимит архива;
- status exit 4 после остановки control API;
- offline status и bundle show после остановки агента;
- рестарт из кэша с недоступным control API (существующая проверка).

На подготовленной Linux машине с root и netlab-зависимостями выполнить сначала
агентский сценарий, затем весь netlab; после отдельного исправления enrollment
clock-тестов повторить make check:

```sh
python3 -m pytest tests/netlab/test_p3_agent.py -v
make netlab PYTHON=python3
make check PYTHON=python3
make parity PYTHON=python3
```

Не повышать привилегии и не запускать на production-хосте без понимания netlab
окружения. Не помечать P3-07 окончательно done только на основании unit-тестов.

## Точка продолжения

Сначала ревью рабочего дерева (включая новые untracked файлы), затем privileged
netlab и замечания. Не переключать ветку с потерей этих изменений. Коммит/merge/
push — только по разрешению владельца. После принятия P3-07 следующая задача —
P3-08: общий хабовый service layer + korctl/API/GUI с parity; backup и 4-VM e2e
не входят в эту передачу.

## Повторное ревью 2026-10-18 (code-reviewer, security-reviewer)

- **Исправлено (HIGH):** `kornode-agent diag` при живом агенте возвращал `[redacted]` вместо архива —
  правило «строка base64» редактора съедало `archive_b64`. Теперь архив отдаётся мимо редактора
  (`_diag` редактирует упакованные файлы сам); тест `test_local_diag_returns_a_decodable_archive_not_a_redaction`.
- **Исправлено (LOW):** строки из строчного hex (sha256), а также значения под ключами `*pubkey`,
  `fingerprint`, `sha256`, `digest` больше не маскируются — иначе `bundle show` не позволял проверить
  ротацию ключа. Одиночная строка base64 неизвестного происхождения по-прежнему маскируется.
- **Открыто (LOW):** `build_report` запускает полный `doctor` (`nft --version`, `nft -j list ruleset`,
  таймаут 10 с каждый) на каждом отчёте/`status`/`diag`; предложено кэшировать результат на пару минут.
