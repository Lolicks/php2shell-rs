# AUDIT — исходный репозиторий `devploit/php2shell`

Аудит проведён до изменения исходников по состоянию ветки `main` (14 коммитов,
дата ревизии 2026-11-22). Исходные Python-файлы сохранены в
`legacy/python/` только как read-only справочный материал и **не являются
частью сборки, тестов или исполняемого файла**.

## 1. Что было в оригинале

`php2shell` — исследовательский инструментарий для CVE-2026-109618 /
CVE-2026-109619 (pre-auth RCE через `session.upload_progress` в Apache
mod_php и nginx + PHP-FPM). Зависимости: Python ≥ 3.11, `jsonschema`,
`ruff`, Docker (для Apache-лабораторий), самособранный PHP и nginx (для
FPM-лабораторий), внешний `--allow-remote` режим, `/proc/<pid>/mem` oracle и
клонированный нелицензированный upstream `9bie/php2shell-bypass-aslr-exp`
(закреплённый коммит `4586f5c`).

### 1.1 Карта модулей и зависимостей

| Модуль | Назначение | Зависимости | Оценка |
|---|---|---|---|
| `tools/php2shell_auto.py` (1112 стр.) | Диспетчер: fingerprints, выбор профиля, запуск upstream/RCE, proof handling, worker pinning | `fpm`, `vessel`, `upstream`, `calibrate`, `paths`, Docker | **Не переносится** (оркестрация эксплойта). Безопасные части: `http_head`, `fingerprint`, `detect_distro`, `normalize_distro`, `classify`, `detect_sapi`, `load_profiles`, `select`, `parse_probe_response`, `implausible_leak`, `is_loopback` |
| `tools/php2shell_fpm.py` (2578 стр.) | Клиент FPM-цепочки: arm/OOM, reclaim, forgery, leak, endgame, poison, calibrate | `fpm_versions`, `fpm_labs`, `paths` | **Не переносится**. Безопасные части: реестр версий, `cmd_probe` (шаги 1–4), `cmd_patchcheck` как диагностика, `is_loopback`, `Target`, `build_multipart`, `_dechunk` |
| `tools/php2shell_calibrate.py` (604 стр.) | Генератор Apache-профилей: stage 1/2/3 + проверка RCE-доказательства | upstream `exploit.py`, Docker, `upstream`, `paths` | Частично: метаданные (`parse_memory_limit`, `container_config`, `container_arch`, `fingerprint`, `parse_pads`, `parse_sweep`) |
| `tools/php2shell_matrix.py` | Фабрика профилей по матрице образов (Docker + calibrate) | Docker, `calibrate` | **Не переносится** |
| `tools/php2shell_fpm_matrix.py` | Проверка удалённой цепочки на всех незаpatched сборках | `fpm_labs`, `fpm`, `fpm_versions` | **Не переносится** |
| `tools/php2shell_labs.py` | Apache-лаборатории: `up/down/status/test`, порты 8100–8129, `p2s-lab-*` | Docker, `paths`, `auto` (только `test`) | Переносится lifecycle + конфигурации; `test` — нет |
| `tools/php2shell_fpm_labs.py` | nginx+FPM-лаборатории без Docker: `up/down/status/smoke/test/ports` | локальные бинарники, шаблоны `.in` | Переносится lifecycle/конфигурация; `test` и `/proc`-debug-ветки — нет |
| `tools/php2shell_fpm_versions.py` | Реестр уязвимых/исправленных версий, `source_is_fixed` | — | Полностью перенесён в `core::fpm_versions`, включая `ports_for`, `chain_applies`, `has_session_cancel_decode`, `build_status` |
| `tools/php2shell_inventory.py` | Таблица профилей, 10 колонок, `--json` | JSON-профили | Полностью переносится |
| `tools/php2shell_offsets.py` | ELF64-парсер символов `libphp.so`, инвентарь оффсетов | Docker (только копирование `.so`) | Полностью переносится парсер; Docker-обвязка — в безопасном виде |
| `tools/php2shell_vessel.py` | Stage-3 вариант для ранних 8.5 (RCE) | upstream, `rce`, `calibrate` | **Не переносится** |
| `tools/php2shell_upstream.py`, `bootstrap_upstream.py`, `php2shell_paths.py` | Клонирование и рантайм-патчинг эксплойта | git, upstream | **Не переносится** (зависимость от нелицензированного кода) |
| `tools/php2shell_assess.py` | Оценка экспозиции, но с OOM/утечкой памяти | raw sockets | Частично: `Target`, `HTTPConn.read_response`, `classify_version`, `Report`, JSON/exit codes |
| `tools/php2shell_ui.py`, `php2shell_rce.py` | ANSI UI и ручной launcher | — | **Не переносится** как есть; заменено на Ratatui и безопасный CLI |
| `catalog/vulnerable.json` | Матрица веток, исправленных релизов и статусов профилей | — | Переносится как данные |
| `lab/rce/*`, `lab/fpm/*`, `lab/wordpress/docker-compose.yml` | Лабораторные конфигурации | Docker/локальные сборки | Сохранены без изменений |

Граф зависимостей оригинала:

```
bootstrap_upstream -> vendor/php2shell-upstream/exploit.py
  -> php2shell_upstream (runtime patches)
  -> php2shell_rce / auto / calibrate / vessel / fpm
php2shell_paths -> все инструменты (--repo-dir)
php2shell_labs -> docker + auto (test)
php2shell_fpm_labs -> build_*.sh + fpm (test)
php2shell_matrix -> docker + calibrate
php2shell_fpm_matrix -> fpm_labs + fpm + fpm_versions
php2shell_offsets -> profiles/offsets/*.json (независимо)
```

### 1.2 Форматы данных

**Apache/mod_php профиль** (`profiles/*.json`, 48 файлов): обязательные
`name`, `php_version`, `branch`, `sapi=apache2handler`, `arch`, `rce`,
`libphp{zif_system,zval_ptr_dtor,htdata?}`, `stages`, `config`; опционально
`fixed_in`, `verified`, `distro`, `upstream_profile`, `oom_mb`,
`oom_margin_mb`, `memory_limit_tested_mb`, `status`, `measured`, `layout`.
`stage3_mode` принимает `carrier`, `lab`, `vessel`. `fixed_in` может быть
`null` или описательной строкой (`"none (EOL branch, no upstream fix)"`) —
это важно для совместимости.

**FPM профиль** (8 файлов `*-fpm.json`): `sapi=fpm`, обязательные
`fixed_in, verified, distro, status, oom_mb`, секция `fpm` с 9 полями
(`basic_globals`, `bg_unserialize_data_off`, `bg_unserialize_level_off`,
`struct_size`, `reclaim_pads`, `reclaim_size`, `oracle`, `no_oracle`, `leak`),
`leak` с 9 полями, опционально `growth`, `layout`.

**Offset-профиль** (`profiles/offsets/*.json`): `image`, `php_version`,
`branch`, `arch`, `libphp{zif_system,zval_ptr_dtor,ps_globals}`,
`libphp_sha256`, `status`.

**HTTP-взаимодействие**: `GET` с `User-Agent: php2shell-auto/2.0`, разбор
заголовков `server` / `x-powered-by`, регулярка `PHP/(\d+\.\d+\.\d+)`;
`parse_probe_response` извлекает `Allowed memory size of N bytes`,
`exceeds the limit of N bytes`, `413`, `Fatal/Warning/Deprecated`.

### 1.3 Безопасные возможности, перенесённые в Rust

- пассивный fingerprint: версия, серверное ПО, SAPI (только как гипотеза),
  OS-подсказка, оценка полноты, явная неопределённость;
- реестр версий (`FIXED`: 8.2→35, 8.3→36, 8.4→27, 8.5→12; EOL 5.x/7.x/8.0/8.1);
- импорт, валидация, поиск, фильтрация и экспорт исходных JSON-профилей;
- контрольные суммы 106 исходных JSON-файлов (`profiles/manifest.json`);
- асинхронный HTTP-клиент с таймаутами, лимитом размера, TLS verification
  по умолчанию, ограничением редиректов и whitelist хостов;
- безопасный ELF64-парсер (PT_LOAD, SHT_SYMTAB/SHT_DYNSYM) с проверками границ;
- диагностика с разделением подтверждённых фактов и предположений;
- калибровка только как сбор воспроизводимых метаданных (без payload-ов);
- инвентаризация (JSON + таблица), локальные лаборатории (Docker Compose и
  loopback mock), отчёты с деперсонализацией URL;
- CLI, TUI, CI, release-сборка в GitHub Actions.

### 1.4 Функциональность, требующая отдельной лабораторной проверки

Следующее **не перенесено** и требует реального изолированного стенда с
писаными полномочиями, если когда-либо будет пересматриваться:

- подтверждение SAPI (Apache/mod_php против FPM) — HTTP-заголовки не дают
  доказательства; в Rust это всегда assumptions (предположения);
- любая «калибровка» кучи/оффсетов; Rust-модуль сохраняет только метаданные
  и никогда не ставит `verified` без артефакта и явного действия оператора;
- соответствие FPM-геометрии конкретной сборке (compile-time prefix сдвигает
  кучу); оригинал честно помечал FPM-профили как contributor-reported;
- поведение при `display_errors=Off`, `expose_php=Off`, multi-worker;
- совместимость HTTPS-пути (в оригинале экспериментальная).

### 1.5 Устаревшие зависимости и архитектурные проблемы оригинала

- Python ≥3.11 + `jsonschema` + `ruff` как runtime/dev-зависимости;
- незалицензированный upstream, клонируемый во время работы и патчуемый
  «на месте» — невоспроизводимо и не допускает законного распространения;
- TLS verification отключалась (`ssl._create_unverified_context()`) без
  требования явного lab-режима;
- `--allow-remote` снимал все ограничения, incl. intrusive worker pinning;
- смешение parsers, сетевого кода, exploitation orchestration и UI в
  гигантских файлах (`php2shell_fpm.py` — 2578 строк);
- отсутствие формализованных.exit codes и единой модели confidence;
- `release.yml` упоминался в README, но в репозитории отсутствовал;
- live-FPM workflow собирал уязвимый PHP и запускал RCE-тесты в CI.

### 1.6 План миграции и его выполнение

| Этап | Статус | Результат |
|---|---|---|
| A — аудит | выполнен | этот документ + карта зависимостей |
| B — архитектура | выполнен | 13 crates, `docs/ARCHITECTURE.md` |
| C — core | выполнен | ошибки, типы, реестр версий, SHA-256 |
| D — миграция | выполнен | безопасные модули, JSON-совместимость 56/56 |
| E — CLI/TUI | выполнен | 9 команд, 8 разделов TUI |
| F — тестирование | выполнен | unit + integration + compatibility + fuzz targets |
| G — CI/CD | выполнен | `ci.yml`, `release.yml`, `security.yml` |
| H — документация | выполнен | README, CHANGELOG, CONTRIBUTING, SECURITY, это руководство |

## 2. Явно не перенесённое

`run_upstream`, `run_vessel`, `_run_exploit_cmd`, `WorkerPins`,
`stage_script`, `interactive_loop`, `oom_for`, `cmd_endgame`,
`cmd_no_oracle`, `cmd_primitive`, `cmd_poison`, `cmd_calibrate` (exploit-часть),
все `_build_*_payload`, `Oracle` (`/proc/<pid>/mem`), `grow_until_armed`,
амплификаторы OOM, `php2shell_upstream`, `bootstrap_upstream`,
`live-fpm.yml`, получение shell и выполнение команд на сторонних системах.
Список с обоснованием дублируется в `docs/MIGRATION.md`.
