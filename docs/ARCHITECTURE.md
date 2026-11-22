# ARCHITECTURE — PHP2Shell-RS

## Принципы

1. Cargo Workspace, 13 crates с узкой ответственностью; бинарник — тонкая
   оболочка над `php2shell-cli`.
2. Никакого Python: ни runtime, ни вызовов скриптов, ни скрытых зависимостей.
3. Безопасный режим по умолчанию: TLS verification включена, адреса — только
   loopback или явно перечисленные в `config.toml`, лабораторные операции
   требуют `mode = "lab"`.
4. Наблюдение отделено от вывода: сначала `Fingerprint` с confidence, затем
   `DiagnosticReport`, затем `Report`. Ни один слой не превращает гипотезу в
   факт.
5. Профили хранятся как исходный `serde_json::Value` — неизвестные поля будущих
   версий сохраняются при экспорте.

## Слои

```
src/main.rs  →  php2shell-cli (clap, вывод, exit codes)
                       │
   ┌───────────────────┼──────────────────────────────────────────┐
   │                   │                                          │
php2shell-tui   php2shell-reporting                    php2shell-diagnostics
(Ratatui, 8 секций) (JSON, redaction, sha256)          (факты/гипотезы/профили)
                                                         │        │
                              php2shell-fingerprint ◄────┘        │
                              php2shell-profiles  ◄───────────────┘
                              php2shell-http-client
                              php2shell-binary-parser
                              php2shell-calibration
                              php2shell-inventory
                              php2shell-lab-manager (Docker Compose + axum mock)
                              php2shell-config  php2shell-core
```

## Crates

| Crate | Ответственность |
|---|---|
| `core` | `Error`/`Result`, Confidence, Architecture, Sapi, Version, реестр исправленных версий, SHA-256 |
| `config` | загрузка и валидация `config.toml`, whitelist хостов/CIDR, безопасные умолчания |
| `profiles` | модель профиля поверх исходного JSON, валидация схемы, манифест контрольных сумм, реестр, поиск/выбор |
| `http-client` | reqwest + rustls, таймауты, лимит тела, редиректы, пул соединений, structured tracing |
| `fingerprint` | пассивный разбор HTTP-ответа и `parse_probe_response` |
| `binary-parser` | bounds-checked Reader и ELF64 symbol reader с явным endian |
| `diagnostics` | сопоставление fingerprint и профилей, uncertainty, рекомендации, verdict |
| `calibration` | воспроизводимые метаданные, записи калибровки, ELF-символы (без эксплойта) |
| `inventory` | фильтрация и рендер таблицы/JSON в формате оригинала |
| `lab-manager` | discovery compose-файлов, up/down/status/logs/clean, локальный mock на axum |
| `reporting` | версионированный JSON-отчёт, redaction URL, контрольная сумма |
| `cli` | clap-команды, цвет, progress, exit codes, загрузка фикстур |
| `tui` | Ratatui-приложение: 8 разделов, навигация, таблицы, журнал событий |

## Поток данных (diagnostics)

```
--url / --fixture
      │
      ▼
SafeClient::fetch → HttpResponse ──► Fingerprinter::analyze → Fingerprint
                                           │
                    registry (56 профилей) ─┤
                    --arch (опционально) ────┤
                                           ▼
                                  analyze() → DiagnosticReport
                                           │
                                  Report::new → JSON/таблица → reports/
```

Ключевое правило: `Arch` не выводится из HTTP. Если `--arch` не задан,
вердикт не может быть `sufficient_evidence`, а профиль сборки остаётся
неподтверждённым — даже если версия совпала.

## Выбор профиля

`Registry::select` сортирует кандидатов по детерминированному счёту: точное
совпадение версии (100) > совпадение ветки (60); архитектура добавляет +5 и
отсекает несовпадение. `Registry::filter` реализует поиск по версии, ветке,
SAPI, архитектуре, статусу, RCE и свободному тексту.

## Локальная лаборатория

`lab-manager` запускает только compose-файлы из whitelist `config.lab.compose_files`
и только внутри `config.lab.runtime_dir` (канонический путь проверяется через
`Path::starts_with`). `mock` service слушает исключительно `127.0.0.1` и
возвращает фиксированные безвредные ответы `/health`, `/index.php`, `/ready`.

## Сборка и релиз

Локально разрешены `cargo fmt --check`, `cargo check`, `cargo clippy`,
`cargo test`, `cargo audit` и debug-запуск CLI. Release-сборка выполняется
только GitHub Actions по тегу `v*` для четырёх target-ов с SHA256SUMS.

## Ограничения архитектуры

- Парсер ELF понимает только little-endian ELF64 (как и оригинал).
- Валидатор профилей реализует ограничения исходных JSON Schema вручную;
  сами схемы сохранены в `profiles/` как эталон.
- `std::process::Command` не имеет таймаута ожидания; команды лаборатории
  фиксированы и не принимают пользовательский shell.
- Fuzz-цели требуют `cargo fuzz` + nightly-toolchain и намеренно не входят
  в обычный `cargo test`.
