//! Binary entry point. All behaviour lives in `php2shell-cli`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let code = php2shell_cli::run(std::env::args_os());
    ExitCode::from(code as u8)
}
