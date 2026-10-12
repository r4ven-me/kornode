# Prompt for the next session — finish P2 (hub cut-over), then P3+

Paste everything below the line into a fresh Claude Code session started in
`/home/lans/Cloud/Projects/public/kornode`. Start on **Sonnet**.

---

Продолжаем редизайн kornode (hub+agents, один reconciler). Язык общения — русский, обращайся ко мне «Ivan».
Прочитай по порядку: `CLAUDE.md`, `AGENTS.md`, `docs/redesign/ROADMAP.md`,
`docs/redesign/DECISIONS.md` (особенно D-20…D-29), `docs/spec/03`, `04`, `10`,
затем память Serena проекта `kornode`: `redesign/p0-session-2026-10-11` и `redesign/p1-netlab`.
Активируй проект Serena `kornode` до поиска по коду.

## Правила работы (важно, это про стоимость)
- **Меньше коммитов**: один коммит на задачу ROADMAP (P2-08, …), короткое тело; не коммить каждую подзадачу.
  Без отдельных веток под каждую мелочь — одна ветка на задачу. Ничего не пушить — пуш я скажу сам, в конце.
- Короткие отчёты. Не перечитывай файлы, которые уже читал в этой сессии.
- **Обратной совместимости нет (D-29).** Не пиши миграций/очисток старого состояния, не оставляй старый и новый код вместе.
- Код пишет codex по узким промптам (`codex exec`, всегда `< /dev/null`; обёртка — `/tmp/codex_task.sh <prefix> <promptfile> [repo]`,
  если её нет — создай: запуск с `-s workspace-write`, stdin закрыт, по завершении пишет `/tmp/<prefix>.done`). Его дифф ты проверяешь сам.
  Если codex упёрся в квоту («usage limit») — пиши сам, не жди.
- Реальные сетевые тесты — только на VM `lans@192.168.122.30` (sudo без пароля, venv в `~/kornode/.venv`):
  `rsync -az --delete --exclude .venv --exclude __pycache__ --exclude artifacts --exclude frontend/node_modules ./ lans@192.168.122.30:~/kornode/`
  затем `ssh lans@192.168.122.30 "cd ~/kornode && sudo make netlab"`. Никогда не запускай привилегированные контейнеры/netns на этой
  (dev) машине: тут продакшн-контейнер `kornode:raven`.
- Перед ответом мне при остановке/вопросе шли уведомление в Telegram (см. память `feedback_telegram_notify`).
- **Скажи мне, когда переключиться на Opus** (см. ниже), не переключайся молча и не проси без причины.

## Состояние (на момент передачи)
Локальный `main` содержит P0+P1 (всё проверено netlab на VM). Ветка `redesign/p2-08c-cutover` (стек P2-01…06, 07, 10(1/2), 11(wip), 08(1-3))
ещё не влита в `main`. Если codex-worktree `/home/lans/Cloud/Projects/kornode-wt-ui` (ветка `redesign/p2-ui`) закончил — смержи его в стек
(он расставляет `data-capability` в `frontend/src` и добавляет вкладку Network); если нет — проверь `git worktree list` и `/tmp/codex_ui.*`.
Готово в `backend/kornode/net/`: `state`, `diff`, `addressing`, `model`, `compile`, `nftgen`, `kernel` (pyroute2+nft, DOCKER-USER compat),
`reconciler` (NL-10: восстановление за ~0.3 с), `explain`. Хаб-часть: `config/legacy.py` (v1-ключи → EgressPolicy),
`services/netinputs.py` (`HubNetInputs`), `services/net.py` (`NetService`, `run_reconciler`), `korctl net plan|apply|explain|run`, `/api/net/*`.
Ловушки pyroute2/nft (уже учтены в `kernel.py`, не наступай заново) — в докстринге `kernel.py` и в D-22…D-28.

## Задача 1: P2-08 + P2-09 — перевод хаба на reconciler (одной задачей, одним коммитом)
Цель ROADMAP P2 «Done when»: **nft и мутации ip rule/route существуют ровно в одном модуле** (`net/kernel.py`).
1. Удали `services/nftables.py` (`NftablesService`), `services/policy_routing.py`, `renderers/nftables.py` (кроме `carrier_state_dir`/`carrier_addresses` —
   перенеси в `kornode.net`/netinputs), шаблоны `templates/nftables*.nft.j2`, `services/sysctl.py` как исполнитель (проверка значений для doctor оставь/перенеси).
   Удали `korctl nft *`, соответствующие маршруты в `api/routes_routing.py` (apply/show/cleanup nft) и их UI/parity-записи; если маршруту нужна замена — `net plan/apply`.
2. `UpstreamService` (`connect/disconnect/switch_profile/recover/ensure_policy_routing/enforce_profile_enablement/apply_server_routing_if_changed`):
   больше никаких вызовов nft/ip rule/route. Они только обновляют входы (файл активного профиля, `install_carrier_exclusion` теперь = запись адресов
   в `upstream-carrier/<profile>.addrs` БЕЗ `ip rule`; pushed-маршруты) и будят reconciler (`NetService.apply()` → сокет `generated_dir/reconciler.sock`,
   иначе один проход in-process). Порядок в `connect()`: записать carrier-адреса → разбудить reconciler → только потом диал (carrier не должен быть помечен, D-20).
   Отказ применения теперь ошибка reconciler с backoff, а не молчаливый успех (так было в v1 — баг).
3. `domain_resolver.py`: вместо `nft -f` с `_dynamic`-наборами пишет `generated_dir/resolved/<set>.txt` (имя набора = как в `NodeFacts.resolved`, D-25) и будит reconciler.
4. `main.py initialize_runtime`: вместо `SysctlService.apply_global` — один `NetService.apply()`; сбой фатален (как раньше для sysctl).
   Хук `vpnc-script-kornode`/`ocserv-connect-script-kornode` (`korctl server hook`, `upstream hook`): вместо `apply_interface` — `net apply` (wake) — sysctl интерфейса ставит reconciler по netlink.
5. `templates/supervisor.conf.j2`: программа `reconciler` (`korctl net run`), `autorestart=true`, стартует ДО `upstream-watchdog`/`api`.
6. `doctor` (`services/doctor.py`): проверки по новому состоянию (`NetService.plan()` пуст = «ядро соответствует политике», sysctl, перекрытия, carrier/exit-таблицы).
7. Тесты: обнови юнит-тесты (удали тесты удалённого кода, не ослабляя остальные), netlab-сценарии P0/P1 (`tests/netlab/test_p0_upstream.py`, `kornode_nodes.py`:
   метки/таблицы теперь `0x0c000100|…`/`12001+…`, а не `0x0c01/1201`; читай их из `HubNetInputs.compiled()`), плюс **grep-тест**: подстроки
   `"nft"`, `"ip", "rule"`, `"ip", "route"` (мутации) встречаются в `backend/kornode` только в `net/kernel.py`.
8. Критерии: полный `make check`, `make parity`, фронт test/build, `sudo make netlab` на VM — всё зелёное, включая все P0/P1 сценарии, NL-10 и «ядро после connect не имеет расхождений с планом».
Обнови `CHANGELOG.md`, `PLAN.ru.md` (чекбоксы Фазы 2), ROADMAP P2 — одной правкой в этом же коммите. Затем влей стек в `main` fast-forward (без пуша).

**Когда переключаться на Opus:** только если после шага 2 (переписывание `UpstreamService`) netlab-сценарии P0/P1 падают и причина не
находится за 2 попытки на Sonnet, или нужно принять архитектурное решение вне ТЗ (напр. как разбудить reconciler из процесса без доступа к сокету). Скажи мне об этом прямо, с причиной.

## Дальше (отдельными сессиями, не в этой): P3 control plane + агент, P4 фабрика, P5 egress GA
Каждая — свежая сессия. Для P3/P4 нужны остальные 3 VM (192.168.122.173/.152/.237, см. README пакета) и e2e на них.
Для архитектурного старта P3 (формат бандла, подпись, apply-with-confirm) имеет смысл начать на Opus в режиме плана, дальше код — на Sonnet.
