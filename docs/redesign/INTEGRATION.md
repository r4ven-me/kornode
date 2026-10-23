# Interlink / Nodes — интеграционная ветка

## Статус

Работа находится в `redesign/interlink-nodes-integration`, а не в `main`.
Она не является опубликованным релизом и не развёртывается автоматически.

- `9b9ee4d` — контрольный коммит всей ранее незакоммиченной переделки:
  переименование interlink, Nodes, совместимость, тесты и история приёмки.
- Интегрирована база `origin/main` на `33df415a82838f275fd75178b250fc7a7be863a3`:
  аудитные исправления PR #5, версия 1.2.0 и исправление обработчика логов PR #7.
- По последнему указанию владельца никакие VPS, SSH, удалённые артефакты и
  окружения не использовались. Релиз, публикация образов и деплой не запускались.
- Изменения дизайна сверх уже сделанного объединения Nodes не придумывались:
  следующие UX-доработки согласуются отдельно.

## Что совмещено

### Конфигурация и безопасность

- Канонические `interlink`, `kornode.lan`, bundle/v2, агент 2.1.0.
- Чтение старых YAML/env/.env, правил, `agent.yaml` и подписанных v1-кэшей;
  конфликтующие aliases отвергаются. Подпись и sealing AAD проверяются до
  нормализации; существующие данные и certificate pins сохраняются.
- Аудитные транзакции latest raw config под общим lock, ETags, сохранение ссылок
  на секреты, очистка validation errors и корректный environment context
  symlink-путей, включая явный `--env-file` в Interlink CLI.
- Защита MFA/сессий, повторная проверка полномочий и сериализованные runtime
  render-пути не заменены старой реализацией при разрешении merge-конфликтов.
- Перенос legacy certificate key использует staged validated publication;
  исходные legacy-файлы не удаляются.

### Сеть

- Стабильные exit marks, точные 128-битные conntrack identities, проверка
  коллизий и fail-closed barriers из аудита сохранены.
- Зарезервированная interlink mark `0x0c800100` соответствует каноническому
  имени, а не попадает в hashing остальных выходов. Старое написание правила
  нормализуется до компиляции. Добавлены проверки alias equivalence,
  reorder/removal/offline guards; golden-наборы пересозданы штатным генератором.
- `upstream:active`, pinned named profiles, disabled exits и DNS
  last-known-good из актуального main сохранены.
- Проверки существующего upstream check_host после трёх провалов останавливают
  зависший retrying openconnect и вызывают reconciler до нового дозвона.

### Панель

- Nodes → Overview / Settings / DNS вместо двух отдельных разделов;
  повторные настройки Interlink из Config удалены.
- Сохранены аудитные password/MFA flows, control settings, nullable group
  inheritance, структурированные Source/DestSet и ETag-конфликты YAML-редактора.
- Общий редактор правил используется и у hub, и у агента; source editing
  остаётся единственным в Network, переход из Nodes фокусирует его.
- Field-inventory покрывает 22 поля ControlConfig/Source/DestSet и nullable
  group booleans. Это не заявление о доказанном паритете каждого AppConfig-поля.

## E2E-06: что исправлено и что не доказано

В тестовом access-client hook найден воспроизводимый локально дефект:
обрабатывался только `reason=connect`. После `reason=reconnect` маршруты могли
не восстановиться. Hook теперь обрабатывает оба события и использует
идемпотентные `addr/route replace`.

Регрессии выполняют настоящий сгенерированный hook с fake `ip`, моделируют
потерю маршрутов и проверяют split/full reconnect без нового login. Дополнительно
проверено, что upgrade заменяет только node, не независимый client container,
а старый успешный observer sample не удовлетворяет post-upgrade recovery.

Порог 30 секунд, VPN-route, ожидаемый exit IP и свежий успешный probe не ослаблены.
Это **не доказательство**, что именно потеря маршрутов вызвала прежний VM-прогон
`3168f99d0b3d4658ce3519b0`. Живой E2E-06 и сетевую приёмку на объединённом коде
не запускали. См. `tests/e2e/ACCEPTANCE-2026-10-23.md`.

## Локальные проверки объединённого кода

- `PYTHONPATH=backend:. .venv/bin/python -m pytest -m 'not netlab and not e2e' -q --tb=short`
  — **2014 passed, 122 deselected**.
- Ruff — passed; mypy backend — **149 files**, E2E — **9 files**, passed.
- `make render parity` с `PYTHONPATH=backend:.` — passed, parity **4 passed**.
- `npm --prefix frontend test` — **84 passed**.
- `npm --prefix frontend run build` — passed.
- `npm --prefix frontend run test:e2e -- --workers=4 --timeout=15000`
  — **49 passed**, только mock-local browser tests.

Исторические 83 netlab-сценария и прежние VM-прогоны относятся к коду **до**
этой интеграции и не заменяют новую runtime-приёмку. Root/network namespace,
production, upgrade и kernel/nftables compatibility здесь не заявляются.

## До следующего релиза

1. Согласовать дальнейшие UX-доработки владельца. Не считать текущий UI принятым.
2. Отдельно исправить известный сценарий первой активации нового пути TLS
   сертификата: reload ocserv 1.5.0 может оставлять `cannot find snapshot for file`;
   нужен корректный выбор restart и регрессия. Диагноз известен из предыдущей
   сессии, новых серверных действий в интеграционной работе нет.
3. Когда владелец разрешит runtime-проверки: проверить E2E-06 на совместимой
   отличающейся базе, полный netlab и end-to-end поведение. Не списывать
   совместимый upgrade на старый SNI flag-day и не снимать assertions.
4. Отдельным решением: версия, release notes, PR/merge в main, новые образы.
   Сейчас версия релиза не повышалась; совпадение project metadata с 1.2.0
   не означает, что development tree соответствует опубликованному образу.
