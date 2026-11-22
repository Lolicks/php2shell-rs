#![no_main]

use libfuzzer_sys::fuzz_target;
use php2shell_binary_parser::{Endian, Reader};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let endian = if data[0] & 1 == 0 {
        Endian::Little
    } else {
        Endian::Big
    };
    let mut reader = Reader::new(&data[1..], endian);
    while reader.remaining() > 0 {
        let before = reader.pos();
        match reader.u64() {
            Ok(_) => {}
            Err(_) => break,
        }
        if reader.pos() == before {
            break;
        }
        let _ = reader.u32_at(reader.pos().saturating_sub(4));
        let _ = reader.cstring_at(reader.pos().min(data.len()), 32);
    }
    let _ = reader.skip(usize::MAX);
});
