# PHP2Shell-RS

**Самостоятельный Rust-инструмент диагностики PHP-сборок и локальных лабораторий.**

PHP2Shell-RS — это не обёртка над Python и не порт эксплойта. Это новая
архитектура на Rust, которая переносит **безопасную диагностическую
функциональность** исходного исследовательского проекта
[`devploit/php2shell`](https://github.com/devploit/php2shell) и сохраняет
совместимость с его JSON-профилями.

> Инструмент не получает shell, не выполняет команды на удалённых системах,
> не отправляет OOM-нагрузку, не читает память процессов и не сканирует сети.
> См. [MIGRATION](docs/MIGRATION.md) и [SECURITY](docs/SECURITY.md).

## Возможности

- **Пассивный fingerprinting** — версия PHP, серверное ПО, гипотеза о SAPI,
  OS-подсказка, оценка полноты данных и явная неопределённость.
- **Реестр профилей** — импорт, валидация схемы, проверка типов и дубликатов,
  контрольные суммы 106 исходных JSON-файлов, версионирование схемы,
  происхождение и экспорт.
- **Диагностика** — разделение подтверждённых фактов и предположений,
  список совместимых/несовместимых профилей, причины неопределённости и
  рекомендации по обновлению и защите.
- **Безопасный HTTP-клиент** — таймауты, TLS verification по умолчанию,
  лимит размера ответа, ограничение редиректов, whitelist хостов.
- **ELF64-парсер** — безопасное чтение символов `libphp.so` с проверкой
  границ и fuzz-тестами.
- **Калибровка метаданных** — воспроизводимые записи с версией PHP, SAPI,
  ОС, архитектурой, сборкой, датой, версией инструмента и SHA-256 артефакта.
  Никаких payload-ов и автоматических «verified» результатов.
- **Инвентаризация** — поиск и фильтрация по версии/SAPI/архитектуре/статусу,
  вывод в JSON или таблицу.
- **Лаборатории** — управление локальными Docker Compose стендами и
  встроенный loopback mock-сервис; все операции требуют `mode = "lab"`.
- **CLI и TUI** — 9 команд, цветной вывод, exit codes, `--json`, `--verbose`,
  `--quiet` и Ratatui-интерфейс с 8 разделами.

## Архитектура

13 crates в Cargo Workspace. Бинарник — тонкая оболочка над `php2shell-cli`.
Подробности: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
core → config → profiles → fingerprint → diagnostics → reporting → cli → main
                    │            │             │
              binary-parser  http-client   inventory
                    │                           │
              calibration                  lab-manager → tui
```

## Поддерживаемые платформы

| Target | Артефакт релиза |
|---|---|
| `x86_64-pc-windows-msvc` | `php2shell-rs-windows-x64.exe` |
| `aarch64-pc-windows-msvc` | `php2shell-rs-windows-arm64.exe` |
| `x86_64-unknown-linux-gnu` | `php2shell-rs-linux-x64` |
| `aarch64-unknown-linux-gnu` | `php2shell-rs-linux-arm64` |

Локально можно выполнить только `cargo check`, `cargo clippy`, `cargo test`,
`cargo fmt --check` и `cargo audit`. Release-бинарники собираются
исключительно в GitHub Actions.

## Установка

Скачайте нужный бинарник и `SHA256SUMS` из
[GitHub Releases](../../releases), проверьте контрольную сумму:

```bash
SHA256SUMS=/path/to/SHA256SUMS
sha256sum -c "$SHA256SUMS" --ignore-missing
chmod +x php2shell-rs-linux-x64   # Linux
```

Из исходников (debug-сборка для разработки):

```bash
cargo check --workspace --all-targets
cargo test --workspace
cargo run -- --help
```

## Примеры CLI

```bash
php2shell-rs version
php2shell-rs profile list
php2shell-rs profile show php-8.4.26-bookworm-amd64
php2shell-rs profile validate
php2shell-rs inventory --sapi fpm --json
php2shell-rs fingerprint --fixture tests/fixtures/http_response.txt --json
php2shell-rs diagnostics --fixture tests/fixtures/http_response.txt --arch amd64
php2shell-rs diagnostics --url http://127.0.0.1:8787/index.php --arch amd64
php2shell-rs lab list
php2shell-rs lab status docker-compose.yml
php2shell-rs report export --fixture tests/fixtures/http_response.txt \
    --arch amd64 --output reports/diagnostic.json
php2shell-rs elf symbols --file /path/to/libphp.so
php2shell-rs tui
```

`-v` / `-vv` увеличивают подробность, `-q` подавляет информационный вывод,
`--json` включает структурированный вывод, `--color auto|always|never`
управляет цветом. Exit codes: `0` — успех/достаточно данных, `1` —
недостаточно данных для вывода, `2` — ошибка валидации, `3` — конфигурация,
`4` — адрес или операция не разрешены, `5` — I/O, `6` — прочее.

## Конфигурация

Скопируйте `config.example.toml` в `config.toml`. Значения по умолчанию
безопасны: `mode = "safe"`, `tls_verify = true`, loopback-only,
`max_response_bytes = 2097152`, `redact = true`.

```toml
mode = "safe"

[http]
timeout_secs = 10
connect_timeout_secs = 5
max_response_bytes = 2097152
max_redirects = 3
tls_verify = true

[profiles]
directory = "profiles"
manifest = "profiles/manifest.json"
strict = true

[lab]
docker_command = "docker"
compose_files = ["lab/wordpress/docker-compose.yml"]
runtime_dir = "lab"

[report]
format = "json"
output_dir = "reports"
redact = true

allowed_addresses = []
```

Чтобы обратиться к не-loopback адресу, внесите его в `allowed_addresses`
явно (поддерживаются IP, hostname и CIDR). Отключение TLS-проверки возможно
только вместе с `mode = "lab"`.

## Лаборатории

Локальный mock (без Docker) слушает только `127.0.0.1`:

```bash
php2shell-rs lab serve --addr 127.0.0.1:8787
php2shell-rs fingerprint --url http://127.0.0.1:8787/index.php
```

Управление Docker Compose-стендом (требуется `mode = "lab"` в конфиге):

```bash
php2shell-rs lab list
php2shell-rs lab up docker-compose.yml
php2shell-rs lab status docker-compose.yml
php2shell-rs lab logs docker-compose.yml --tail 50
php2shell-rs lab down docker-compose.yml
php2shell-rs lab clean
```

## TUI

`php2shell-rs tui` открывает тёмный интерфейс с разделами Dashboard,
Fingerprinting, Profiles, Inventory, Diagnostics, Laboratories, Reports и
Settings. Навигация: `Tab`/`Shift+Tab`, `1`–`8`, `j/k` или стрелки,
`PageUp`/`PageDown`, `r` — перезагрузка профилей, `?` — справка, `q` — выход.

## Совместимость профилей

Поддерживаются все 56 исходных профилей (48 Apache/mod_php + 8 PHP-FPM) в
неизменённом виде. Исходные JSON, схемы и каталог уязвимостей сохранены; их
SHA-256 записаны в `profiles/manifest.json`. Подробности —
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Ограничения

- Только пассивная диагностика; SAPI и ОС остаются гипотезами без
  подтверждения на стенде.
- ELF-парсер поддерживает только little-endian ELF64.
- Fuzz-цели требуют `cargo fuzz` и nightly и не запускаются в CI.
- Исходная Python-реализация сохранена в `legacy/python/` как архив и не
  используется ни во время сборки, ни во время работы.
- Полный список неперенесённых возможностей — [docs/MIGRATION.md](docs/MIGRATION.md).

## Документация

- [AUDIT](docs/AUDIT.md) — полный аудит оригинала
- [ARCHITECTURE](docs/ARCHITECTURE.md) — архитектура
- [MIGRATION](docs/MIGRATION.md) — что и почему не перенесено
- [COMPATIBILITY](docs/COMPATIBILITY.md) — форматы
- [SECURITY](docs/SECURITY.md) — модель угроз
- [RELEASE](docs/RELEASE.md) — публикация релиза
- [CONTRIBUTING](CONTRIBUTING.md), [CHANGELOG](CHANGELOG.md)

## Лицензия

MIT. License не даёт разрешения на тестирование чужих систем. Используйте
инструмент только с письменного разрешения владельца.
