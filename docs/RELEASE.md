# RELEASE — инструкция публикации

1. Убедиться, что CI зелёный на `main` (fmt, check, clippy, unit,
   integration, compatibility, profile validate, audit).
2. Обновить `CHANGELOG.md` и версию в `Cargo.toml` (`workspace.package.version`
   и `package.version`).
3. Создать и запушить тег вида `v1.0.0`:

   ```bash
   git tag -a v1.0.0 -m "PHP2Shell-RS 1.0.0"
   git push origin v1.0.0
   ```

4. Workflow `.github/workflows/release.yml` для каждого из четырёх target-ов:
   - устанавливает Rust target;
   - выполняет `cargo build --release --locked --target <target>`;
   - проверяет наличие бинарника;
   - запускает `--version` и `--help` на том же runner (все четыре runner-а
     нативные: `ubuntu-latest`, `ubuntu-24.04-arm`, `windows-latest`,
     `windows-11-arm`);
   - упаковывает бинарник вместе с `README.md`, `LICENSE`, `CHANGELOG.md`;
   - создаёт `SHA256SUMS-<target>`.
5. Job `release` скачивает артефакты, объединяет контрольные суммы в общий
   `SHA256SUMS` и публикует GitHub Release с автоматически сгенерированными
   release notes.

## Проверка артефакта пользователем

```bash
sha256sum -c SHA256SUMS --ignore-missing
./php2shell-rs-linux-x64 --version
```

## Запрет локальной release-сборки

`cargo build --release`, ручная упаковка архивов и публикация бинарников
локально запрещены. Разрешены только `cargo fmt --check`, `cargo check`,
`cargo clippy`, `cargo test`, `cargo audit` и debug-запуск через `cargo run`.
