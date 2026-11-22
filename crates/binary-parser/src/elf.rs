//! Read-only ELF64 symbol-table reader (port of the upstream offset
//! inventory parser, rewritten with explicit bounds and endianness).

use crate::reader::{Endian, ParseError, Reader, Result};

const PT_LOAD: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const WANTED: &[&str] = &["zif_system", "zval_ptr_dtor", "ps_globals", "basic_globals"];
const MAX_TABLE_ENTRIES: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    /// Value as stored in the symbol table (relative to the load bias).
    pub value: u64,
    /// Value plus the lowest PT_LOAD virtual address, when it fits.
    pub virtual_address: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfInfo {
    pub bias: u64,
    pub symbols: Vec<Symbol>,
}

#[derive(Clone, Copy)]
struct Section {
    kind: u32,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

fn as_usize(value: u64, what: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| ParseError::Invalid {
        what,
        detail: "value does not fit the host address space".into(),
    })
}

fn bounded_range(
    data: &[u8],
    offset: u64,
    size: u64,
    what: &'static str,
) -> Result<(usize, usize)> {
    let start = as_usize(offset, what)?;
    let length = as_usize(size, what)?;
    let end = start.checked_add(length).ok_or(ParseError::Overflow)?;
    if end > data.len() {
        return Err(ParseError::UnexpectedEof {
            offset: start,
            needed: length,
        });
    }
    Ok((start, end))
}

pub fn parse_elf64(data: &[u8]) -> Result<ElfInfo> {
    if data.len() < 64 {
        return Err(ParseError::UnexpectedEof {
            offset: data.len(),
            needed: 64 - data.len(),
        });
    }
    if &data[..4] != b"\x7fELF" {
        return Err(ParseError::Invalid {
            what: "ELF magic",
            detail: "not an ELF file".into(),
        });
    }
    if data[4] != 2 {
        return Err(ParseError::Invalid {
            what: "ELF class",
            detail: "only ELF64 is supported".into(),
        });
    }
    if data[5] != 1 {
        return Err(ParseError::Invalid {
            what: "ELF endianness",
            detail: "only little-endian ELF is supported".into(),
        });
    }

    let reader = Reader::new(data, Endian::Little);
    let phoff = reader.u64_at(0x20)?;
    let shoff = reader.u64_at(0x28)?;
    let phentsize = reader.u16_at(0x36)? as u64;
    let phnum = reader.u16_at(0x38)? as u64;
    let shentsize = reader.u16_at(0x3a)? as u64;
    let shnum = reader.u16_at(0x3c)? as u64;

    let mut loads = Vec::new();
    if phnum > 0 {
        if phentsize < 56 {
            return Err(ParseError::Invalid {
                what: "ELF program header",
                detail: "e_phentsize is smaller than ELF64".into(),
            });
        }
        let table_size = phentsize.checked_mul(phnum).ok_or(ParseError::Overflow)?;
        let (start, _) = bounded_range(data, phoff, table_size, "program header table")?;
        for index in 0..as_usize(phnum, "e_phnum")? {
            let base = start
                .checked_add(
                    index
                        .checked_mul(as_usize(phentsize, "e_phentsize")?)
                        .ok_or(ParseError::Overflow)?,
                )
                .ok_or(ParseError::Overflow)?;
            let kind = reader.u32_at(base)?;
            let vaddr = reader.u64_at(base + 16)?;
            let memsz = reader.u64_at(base + 40)?;
            if kind == PT_LOAD && memsz > 0 {
                loads.push(vaddr);
            }
        }
    }
    let bias = loads.into_iter().min().unwrap_or(0);

    let mut sections = Vec::new();
    if shnum > 0 {
        if shentsize < 64 {
            return Err(ParseError::Invalid {
                what: "ELF section header",
                detail: "e_shentsize is smaller than ELF64".into(),
            });
        }
        let table_size = shentsize.checked_mul(shnum).ok_or(ParseError::Overflow)?;
        let (start, _) = bounded_range(data, shoff, table_size, "section header table")?;
        for index in 0..as_usize(shnum, "e_shnum")? {
            let base = start
                .checked_add(
                    index
                        .checked_mul(as_usize(shentsize, "e_shentsize")?)
                        .ok_or(ParseError::Overflow)?,
                )
                .ok_or(ParseError::Overflow)?;
            sections.push(Section {
                kind: reader.u32_at(base + 4)?,
                offset: reader.u64_at(base + 24)?,
                size: reader.u64_at(base + 32)?,
                link: reader.u32_at(base + 40)?,
                entsize: reader.u64_at(base + 56)?,
            });
        }
    }

    let mut symbols = Vec::new();
    for section in sections
        .iter()
        .filter(|s| s.kind == SHT_SYMTAB || s.kind == SHT_DYNSYM)
    {
        let entsize = if section.entsize == 0 {
            24
        } else {
            section.entsize
        };
        if entsize < 24 {
            continue;
        }
        let (sym_start, sym_end) =
            bounded_range(data, section.offset, section.size, "symbol table")?;
        let link = as_usize(u64::from(section.link), "sh_link")?;
        let strtab = sections.get(link).ok_or_else(|| ParseError::Invalid {
            what: "symbol string table",
            detail: format!("sh_link {link} is out of range"),
        })?;
        let (str_start, str_end) = bounded_range(data, strtab.offset, strtab.size, "string table")?;
        let count = ((sym_end - sym_start) as u64 / entsize) as usize;
        if count > MAX_TABLE_ENTRIES {
            return Err(ParseError::Invalid {
                what: "symbol table",
                detail: "too many symbol entries".into(),
            });
        }
        for index in 0..count {
            let base = sym_start
                .checked_add(
                    index
                        .checked_mul(as_usize(entsize, "sh_entsize")?)
                        .ok_or(ParseError::Overflow)?,
                )
                .ok_or(ParseError::Overflow)?;
            if base + 16 > sym_end {
                break;
            }
            let name_offset = reader.u32_at(base)? as usize;
            let value = reader.u64_at(base + 8)?;
            if name_offset >= str_end - str_start {
                continue;
            }
            let name_bytes = Reader::new(&data[str_start..str_end], Endian::Little)
                .cstring_at(name_offset, str_end - str_start)?;
            let name = String::from_utf8_lossy(name_bytes);
            if WANTED.contains(&name.as_ref()) {
                let virtual_address = value.checked_add(bias);
                if !symbols.iter().any(|symbol: &Symbol| symbol.name == name) {
                    symbols.push(Symbol {
                        name: name.into_owned(),
                        value,
                        virtual_address,
                    });
                }
            }
        }
    }
    symbols.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ElfInfo { bias, symbols })
}

/// Parses the `0x...` offset format used by the upstream profile files.
pub fn parse_hex_offset(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or_else(|| ParseError::Invalid {
            what: "hex offset",
            detail: "expected a 0x prefix".into(),
        })?;
    if digits.is_empty() {
        return Err(ParseError::Invalid {
            what: "hex offset",
            detail: "no digits after 0x".into(),
        });
    }
    u64::from_str_radix(digits, 16).map_err(|err| ParseError::Invalid {
        what: "hex offset",
        detail: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn push_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn push_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Builds a minimal ELF64 with one PT_LOAD and one SYMTAB whose strtab
    /// contains `zif_system` and an unrelated symbol.
    fn synthetic_elf() -> Vec<u8> {
        let phoff = 64usize;
        let shoff = 64 + 56;
        let symoff = shoff + 3 * 64;
        let stroff = symoff + 2 * 24;
        let mut buf = vec![0u8; stroff + 20];
        buf[..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        push_u64(&mut buf, 0x20, phoff as u64);
        push_u64(&mut buf, 0x28, shoff as u64);
        push_u16(&mut buf, 0x36, 56);
        push_u16(&mut buf, 0x38, 1);
        push_u16(&mut buf, 0x3a, 64);
        push_u16(&mut buf, 0x3c, 3);

        push_u32(&mut buf, phoff, PT_LOAD);
        push_u64(&mut buf, phoff + 16, 0x1000);
        push_u64(&mut buf, phoff + 40, 0x2000);

        // section 0: null; section 1: symtab, sh_link = 2
        push_u32(&mut buf, shoff + 64 + 4, SHT_SYMTAB);
        push_u64(&mut buf, shoff + 64 + 24, symoff as u64);
        push_u64(&mut buf, shoff + 64 + 32, (2 * 24) as u64);
        push_u32(&mut buf, shoff + 64 + 40, 2);
        push_u64(&mut buf, shoff + 64 + 56, 24);
        // section 2: strtab
        push_u32(&mut buf, shoff + 2 * 64 + 4, 3);
        push_u64(&mut buf, shoff + 2 * 64 + 24, stroff as u64);
        push_u64(&mut buf, shoff + 2 * 64 + 32, 16);

        push_u32(&mut buf, symoff, 1);
        push_u64(&mut buf, symoff + 8, 0x465370);
        push_u32(&mut buf, symoff + 24, 11);
        push_u64(&mut buf, symoff + 24 + 8, 0x10);
        buf[stroff + 1..stroff + 11].copy_from_slice(b"zif_system");
        buf[stroff + 11] = 0;
        buf[stroff + 12..stroff + 17].copy_from_slice(b"other");
        buf
    }

    #[test]
    fn parses_synthetic_elf() {
        let info = parse_elf64(&synthetic_elf()).unwrap();
        assert_eq!(info.bias, 0x1000);
        assert_eq!(info.symbols.len(), 1);
        assert_eq!(info.symbols[0].name, "zif_system");
        assert_eq!(info.symbols[0].value, 0x465370);
        assert_eq!(info.symbols[0].virtual_address, Some(0x466370));
    }

    #[test]
    fn rejects_malformed_input_without_panicking() {
        let good = synthetic_elf();
        for len in 0..good.len() {
            let _ = parse_elf64(&good[..len]);
        }
        let mut bad_endian = good.clone();
        bad_endian[5] = 2;
        assert!(parse_elf64(&bad_endian).is_err());
        let mut bad_class = good.clone();
        bad_class[4] = 1;
        assert!(parse_elf64(&bad_class).is_err());
        let mut huge_count = good.clone();
        push_u64(&mut huge_count, 0x28, u64::MAX);
        assert!(parse_elf64(&huge_count).is_err());
    }

    #[test]
    fn parses_hex_offsets() {
        assert_eq!(parse_hex_offset("0x465370").unwrap(), 0x465370);
        assert!(parse_hex_offset("465370").is_err());
        assert!(parse_hex_offset("0x").is_err());
    }
}
