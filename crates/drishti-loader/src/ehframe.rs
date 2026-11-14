//! Minimal `.eh_frame` parser: extracts FDE `pc_begin` values, which are
//! reliable function starts even in stripped, optimised ELF and Mach-O code.

const DW_EH_PE_OMIT: u8 = 0xff;

struct Reader<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.d.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    fn bytes<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.d.get(self.p..self.p.checked_add(N)?)?;
        self.p += N;
        s.try_into().ok()
    }
    fn uleb(&mut self) -> Option<u64> {
        let mut r = 0u64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                r |= u64::from(b & 0x7f) << shift;
            }
            if b & 0x80 == 0 {
                return Some(r);
            }
            shift += 7;
            if shift > 70 {
                return None;
            }
        }
    }
    fn sleb(&mut self) -> Option<i64> {
        let mut r = 0i64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                r |= i64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    r |= -1i64 << shift;
                }
                return Some(r);
            }
            if shift > 70 {
                return None;
            }
        }
    }
    fn cstr(&mut self) -> Option<&'a [u8]> {
        let start = self.p;
        let len = self.d.get(start..)?.iter().position(|&b| b == 0)?;
        self.p = start + len + 1;
        self.d.get(start..start + len)
    }

    /// Read an encoded pointer. `vaddr` is the section address (for pcrel).
    fn encoded(&mut self, enc: u8, vaddr: u64, ptr64: bool) -> Option<u64> {
        if enc == DW_EH_PE_OMIT {
            return None;
        }
        let here = vaddr.wrapping_add(self.p as u64);
        let raw: u64 = match enc & 0x0f {
            0x00 => {
                if ptr64 {
                    u64::from_le_bytes(self.bytes::<8>()?)
                } else {
                    u64::from(u32::from_le_bytes(self.bytes::<4>()?))
                }
            }
            0x01 => self.uleb()?,
            0x02 => u64::from(u16::from_le_bytes(self.bytes::<2>()?)),
            0x03 => u64::from(u32::from_le_bytes(self.bytes::<4>()?)),
            0x04 => u64::from_le_bytes(self.bytes::<8>()?),
            0x09 => self.sleb()? as u64,
            0x0a => i64::from(i16::from_le_bytes(self.bytes::<2>()?)) as u64,
            0x0b => i64::from(i32::from_le_bytes(self.bytes::<4>()?)) as u64,
            0x0c => u64::from_le_bytes(self.bytes::<8>()?),
            _ => return None,
        };
        Some(match enc & 0x70 {
            0x00 => raw,
            0x10 => here.wrapping_add(raw),
            _ => return None, // datarel/textrel/funcrel: not used for pc_begin in practice
        })
    }
}

/// Parse `.eh_frame` bytes located at `vaddr`; returns FDE `(start, len)`.
/// Assumes little-endian (x86, AArch64). Stops quietly on malformed data.
pub fn fde_ranges(data: &[u8], vaddr: u64, ptr64: bool) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    // CIE offset -> FDE pointer encoding.
    let mut cie_enc: Vec<(usize, u8)> = Vec::new();
    let mut r = Reader { d: data, p: 0 };
    let mut guard = 0u32;
    while r.p + 4 <= data.len() {
        guard += 1;
        if guard > 2_000_000 {
            break;
        }
        let entry_start = r.p;
        let Some(len32) = r.bytes::<4>().map(u32::from_le_bytes) else {
            break;
        };
        if len32 == 0 {
            break; // terminator
        }
        let (len, hdr) = if len32 == 0xffff_ffff {
            match r.bytes::<8>() {
                Some(b) => (u64::from_le_bytes(b) as usize, 12),
                None => break,
            }
        } else {
            (len32 as usize, 4)
        };
        let body_start = r.p;
        let Some(next) = entry_start
            .checked_add(hdr)
            .and_then(|v| v.checked_add(len))
        else {
            break;
        };
        if next > data.len() {
            break;
        }
        let id_pos = r.p;
        let Some(id) = r.bytes::<4>().map(u32::from_le_bytes) else {
            break;
        };
        if id == 0 {
            // CIE
            let enc = parse_cie(&mut r).unwrap_or(0);
            cie_enc.push((entry_start, enc));
        } else {
            let cie_off = id_pos.wrapping_sub(id as usize);
            let enc = cie_enc
                .iter()
                .rev()
                .find(|(o, _)| *o == cie_off)
                .map(|(_, e)| *e)
                .unwrap_or(0x1b);
            if let Some(pc) = r.encoded(enc, vaddr, ptr64) {
                // pc_range uses the same format without the application part.
                let len = r.encoded(enc & 0x0f, vaddr, ptr64).unwrap_or(0);
                if pc != 0 {
                    out.push((pc, len));
                }
            }
        }
        let _ = body_start;
        r.p = next;
    }
    out
}

fn parse_cie(r: &mut Reader<'_>) -> Option<u8> {
    let version = r.u8()?;
    let aug = r.cstr()?;
    if aug.contains(&b'e') && aug.contains(&b'h') {
        return None; // ancient GCC "eh" augmentation, unsupported
    }
    r.uleb()?; // code alignment
    r.sleb()?; // data alignment
    if version == 1 {
        r.u8()?;
    } else {
        r.uleb()?;
    }
    let mut enc = 0u8;
    if aug.first() == Some(&b'z') {
        let _aug_len = r.uleb()?;
        for &c in &aug[1..] {
            match c {
                b'R' => enc = r.u8()?,
                b'P' => {
                    let penc = r.u8()?;
                    // skip personality pointer
                    r.encoded(penc & 0x7f, 0, true)?;
                }
                b'L' => {
                    r.u8()?;
                }
                b'S' | b'B' | b'G' => {}
                _ => return Some(enc),
            }
        }
    }
    Some(enc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cie_and_fde() {
        let mut d = Vec::new();
        // CIE: length, id=0, version 1, "zR", code align 1, data align -8, RA 16, aug len 1, enc 0x1b
        let cie_body: &[u8] = &[0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0, 0, 0];
        d.extend_from_slice(&(cie_body.len() as u32).to_le_bytes());
        d.extend_from_slice(cie_body);
        // FDE at offset 20: id = distance back to CIE (offset of id field = 24).
        let fde_id_pos = d.len() + 4;
        let mut fde = Vec::new();
        fde.extend_from_slice(&(fde_id_pos as u32).to_le_bytes());
        // pc_begin pcrel sdata4: target 0x1000 from field at vaddr 0x2000 + 28
        let field_va = 0x2000u64 + (fde_id_pos + 4) as u64;
        let rel = (0x1000i64 - field_va as i64) as i32;
        fde.extend_from_slice(&rel.to_le_bytes());
        fde.extend_from_slice(&0x40u32.to_le_bytes());
        fde.push(0);
        d.extend_from_slice(&(fde.len() as u32).to_le_bytes());
        d.extend_from_slice(&fde);
        d.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(fde_ranges(&d, 0x2000, true), vec![(0x1000, 0x40)]);
    }

    #[test]
    fn garbage_does_not_panic() {
        for seed in 0..200u32 {
            let d: Vec<u8> = (0..64)
                .map(|i| (i as u32).wrapping_mul(seed).wrapping_add(seed) as u8)
                .collect();
            let _ = fde_ranges(&d, 0, true);
        }
    }
}
