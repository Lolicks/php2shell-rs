# MIGRATION — что перенесено, а что намеренно нет

## Перенесено (с тестами)

| Оригинал | Rust-эквивалент | Тест |
|---|---|---|
| `auto.fingerprint`, `assess.fingerprint` | `php2shell-fingerprint::Fingerprinter` | unit + integration fixture |
| `auto.detect_distro/normalize_distro/classify/detect_sapi` | `fingerprint::detect_*`, `core::versions` | unit + compatibility |
| `auto.load_profiles/select` | `profiles::Registry` | unit + integration (56 JSON) |
| `auto.parse_probe_response` | `fingerprint::parse_probe_response` | unit |
| `fpm_versions` (полностью) | `core::fpm_versions`: `branch_of`, `fixed_in`, `is_vulnerable`, `affected_versions`, `ports_for`, `chain_applies`, `source_is_fixed`, `has_session_cancel_decode`, `build_status` | unit + compatibility |
| `cmd_probe` шаги 1–4 | `diagnostics::probe` + CLI `preconditions` (только lab-режим, только безопасные GET/POST, без OOM) | integration |
| `calibrate.parse_pads`, `stage3_profile_json` | `calibration::pad` | unit + integration |
| `offsets.write_doc` | CLI `offsets inventory` | integration |
| `inventory` | `php2shell-inventory` (10 колонок + status/file в JSON) | unit + integration |
| `offsets.parse_elf` | `binary-parser::parse_elf64` | unit + fuzz |
| `calibrate` метаданные | `php2shell-calibration` | unit |
| `labs`/`fpm_labs` lifecycle | `php2shell-lab-manager` | unit + integration |
| `assess.Report` JSON | `php2shell-reporting::Report` | unit + integration |
| `auto.HTTPConn` header parser | `php2shell-http-client` | unit + mock integration |
| `php2shell_ui` | `php2shell-tui` (Ratatui) | unit + render smoke test |

## Намеренно НЕ перенесено

| Функция оригинала | Причина | Безопасная альтернатива в Rust |
|---|---|---|
| `run_upstream`, `run_vessel`, `_run_exploit_cmd` | запуск эксплойта и получение shell | отсутствует; CLI предлагает только диагностику |
| `WorkerPins`, `auto_remote` | насыщение worker-ов, DoS-характер | нет; `--url` должен быть явно указан |
| `probe_config` (16/64/256 MiB POST) | намеренный OOM удалённого сервера | `parse_probe_response` разбирает уже имеющийся ответ |
| `trigger_pre_rinit_oom`, `_amplifier_*`, `grow_until_armed` | OOM/DoS | нет |
| `cmd_endgame`, `cmd_no_oracle`, `cmd_primitive`, `cmd_poison`, `_build_*_payload` | подделка структур, выполнение команд | нет |
| шаг 5 `cmd_probe` (OOM/arm), `grow_until_armed` | намеренный OOM/DoS | в `preconditions` помечается как `skipped` |
| `Oracle` (`/proc/<pid>/mem`) | чтение памяти процесса | метаданные калибровки без oracle |
| `cmd_calibrate` (exploit-часть), `matrix`, `fpm_matrix` | автоматическая эксплуатация и сбор доказательств RCE | `calibration record` с полями воспроизводимости и SHA-256 артефакта |
| `php2shell_upstream`, `bootstrap_upstream` | патчинг нелицензированного эксплойта во время работы | нет; внешний код не загружается |
| `lab*/test`, `live-fpm.yml` | запуск RCE в CI/лаборатории | `lab smoke` через локальный axum mock |
| `--allow-remote` | снимал ограничения на сторонние системы | `allowed_addresses` в конфиге + `--arch` не заменяет разрешение; адрес должен быть явно внесён |
| `patch_tls` / `_create_unverified_context` | отключал проверку TLS | `tls_verify = true` по умолчанию; override только в `mode = "lab"` |

## Что изменилось в данных

Исходные 56 профилей, 2 JSON Schema, каталог уязвимостей и все laboratory-
конфигурации сохранены **без изменений**. Их контрольные суммы записаны в
`profiles/manifest.json` (106 записей). Новые поля (`schema_version`,
`provenance`) опциональны и не добавляются в исходные файлы автоматически.

## Источники риска, устранённые в миграции

1. Удалён dynamically imported upstream exploit (нелицензированный код).
2. Удалены все пути выполнения команд на удалённых системах.
3. Удалены OOM/амплификаторы и worker saturation.
4. Включена проверка TLS по умолчанию.
5. Введена модель confidence и явная неопределённость.
6. Введены exit codes и redaction отчётов.
7. Все release-артефакты теперь собираются только в GitHub Actions.
