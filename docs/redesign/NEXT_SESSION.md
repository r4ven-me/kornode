# Prompt for the next session — netlab, review of follow-ups, four-VM acceptance

> **Состояние на 2026-10-17.** Ветка `redesign/p3-08-agent-management` (поверх P3-06,
> последний коммит `fd0b601`). P3-07…P3-10 реализованы и **не приняты**; блокирующие
> находки ревью исправлены в **незакоммиченном** рабочем дереве (D-59, CHANGELOG →
> «Fixed»). Много файлов untracked — смотри `git status`, а не только `git diff`.
> Коммит, merge, push, запуск на VM/CI — только по отдельному разрешению владельца.

Вставь всё ниже черты в новую сессию Claude Code в
`/home/lans/Cloud/Projects/public/kornode`. Начни в режиме плана.

---

Продолжаем редизайн kornode (hub+agents, один reconciler). Язык — русский, обращайся ко мне «Ivan».
Прочитай по порядку: `CLAUDE.md`, `AGENTS.md`, раздел «Дальнейшие действия» в `docs/redesign/PLAN.ru.md`,
`docs/redesign/CLAUDE-HANDOFF.md`, четыре `P3-0{7,8,9}-REVIEW.md` / `P3-10-REVIEW.md`,
`docs/redesign/DECISIONS.md` (D-29…D-59), `docs/runbooks/hub-recovery.md`, `docs/runbooks/vm-e2e.md`.
Активируй проект Serena `kornode` до поиска по коду.

## Что уже сделано (не переделывай)
- P3-07 (CLI агента), P3-08 (AgentService/ControlManagement, 37 CLI-команд, 32 эндпоинта, раздел Agents),
  P3-09 (encrypted backup/staged restore), P3-10 (four-VM harness, workflow, runbook) — реализованы.
- Исправления по ревью (D-59): shutdown `LocalServer`, lock-free `specs()`, логирование ошибок (только тип),
  расширенный редактор секретов; `_validate(changed=…)`, лимит очереди queued+delivered, `ocpasswd` вне
  транзакции, `rotation.unconfirmed_agents` в `control status`; certbot-симлинки и 0700 в backup;
  e2e: только `workflow_dispatch` с protected branch, `clean: false`, retention 7 дней, `sysctls`;
  фронтенд (секреты при ошибке, показ токена без clipboard, ошибки Backup, запятая в «From»);
  clock-тесты enrollment (часы теста стартуют с реального времени).
- Проверки: `make check` — ruff, `mypy --strict`, **1076 passed / 64 skipped**; `make parity` 4 passed;
  frontend vitest 30 passed + build.
- Сознательно **не** сделано: строгая сверка серийника в `ControlService.authenticate` с `node.cert_serial`
  (при продлении старый сертификат должен оставаться валидным; отзыв — через CRL), см. D-59.
  Промоушен ключа подписи остаётся по таймеру (spec 05).
- Замечание: `ruff format backend tests` случайно прогнан по дереву (~26 файлов, только стиль).
  Проект проверяет `ruff check`; не гоняй `ruff format` по всему репо.

## Окружение
- Используй `.venv` (`make` подхватывает его сам): `.venv/bin/python -m pytest`, `.venv/bin/python -m mypy --strict backend`.
  Системный python не годится (нет `argon2` в `cryptography`).
- Netlab нужен root; VM для него — `192.168.122.30` (не e2e-стенд).
- Сборка `Dockerfile.agent` и любой Docker/VM-прогон на dev-машине не выполнялись.

## Что делать дальше (по порядку)
1. **Ревью текущего диффа** агентами `code-reviewer` и `security-reviewer` (весь tracked + untracked, не только
   последние правки). Новые находки — в `P3-0X-REVIEW.md`, решения — в `DECISIONS.md`.
2. **Привилегированный netlab** на `192.168.122.30`: сценарии P3-07/08/09 (сейчас только skipped) + весь набор.
   Для P3-09 подтвердить активацию восстановленного дерева.
3. **`Dockerfile.agent`**: собрать, записать размер (цель ≤150 МБ).
4. **Хвосты P2:** netlab-сценарий D-32 («exit убран, пока соединение живо» — 0 пакетов на uplink); окно второго
   писателя ядра при старте демона; netlink-события в обход backoff; grep-тест единственного писателя → проверка
   по импортам/AST.
5. **Только после разрешения владельца:** коммиты по задачам (`P3-07`…`P3-10` отдельными коммитами, ID в сообщении),
   затем provisioning четырёх VM и реальный four-VM E2E.
6. Обновить `PLAN.ru.md`, `ROADMAP.md`, `CHANGELOG.md`, этот файл; отчёт по формату из `CLAUDE.md`.

## Что нужно от меня для P3-10 (напомни заранее)
4 VM (`hub`, `agent-a`, `agent-b`, `ext`); адреса под e2e зарезервированы три (`192.168.122.173/.152/.237`),
четвёртый не определён. Self-hosted runner на `hub` — **включать только** при workflow без `pull_request`
(сейчас так) и с protected branch. Нужны: GitHub Environment `kornode-e2e` с approval, SSH-секреты на уровне
environment, ограничение runner group, root-owned маркеры ролей на каждой VM, переменная
`E2E_ENVIRONMENT_APPROVAL_CONFIGURED=true` только при реально настроенной защите.

## Правила
Каждая задача — по `CLAUDE.md`: spec → тесты → код → docs → `make check` → netlab; `parity.yaml` обновляется
в той же задаче. Тесты не ослаблять; если тест кодирует убираемое поведение — удалить в том же PR и сказать об этом.
