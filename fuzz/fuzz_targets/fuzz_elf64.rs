#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser must reject arbitrary bytes without panicking or allocating
    // based on untrusted table sizes.
    let _ = php2shell_binary_parser::parse_elf64(data);
    for token in std::str::from_utf8(data).into_iter() {
        let _ = php2shell_binary_parser::parse_hex_offset(token);
    }
});
