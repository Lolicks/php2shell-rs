//! Bounds-checked binary parsing. No raw pointers, no unsafe code and no
//! exploitation primitives: the only real parser here is a read-only ELF64
//! symbol-table reader used for diagnostic offset inventories.

mod elf;
mod reader;

pub use elf::{ElfInfo, Symbol, parse_elf64, parse_hex_offset};
pub use reader::{Endian, ParseError, Reader};
