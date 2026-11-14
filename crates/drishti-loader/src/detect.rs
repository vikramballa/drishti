//! Format detection by magic bytes (spec §7.1). Extensions are never trusted.

use drishti_model::Format;
use std::io::Cursor;

/// Result of detection, including ZIP sub-classification details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub format: Format,
    /// For fat Mach-O: number of slices.
    pub fat_slices: Option<u32>,
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}
fn le32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// Detect the format of `bytes`. Never panics on any input.
pub fn detect(bytes: &[u8]) -> Detected {
    let d = |format| Detected {
        format,
        fat_slices: None,
    };
    if bytes.len() < 4 {
        return d(Format::Unknown);
    }
    let m = &bytes[..4];
    match m {
        [0x7f, b'E', b'L', b'F'] => return d(Format::Elf),
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xcf, 0xfa, 0xed, 0xfe] => {
            return d(Format::Macho);
        }
        [0xca, 0xfe, 0xba, 0xbe] | [0xca, 0xfe, 0xba, 0xbf] => {
            // Fat Mach-O and Java class share CAFEBABE.
            let n = be32(bytes, 4).unwrap_or(0);
            if n > 0 && n < 30 {
                return Detected {
                    format: Format::MachoFat,
                    fat_slices: Some(n),
                };
            }
            let major = bytes
                .get(6..8)
                .map(|s| u16::from_be_bytes([s[0], s[1]]))
                .unwrap_or(0);
            if m[3] == 0xbe && major >= 45 {
                return d(Format::JavaClass);
            }
            return d(Format::Unknown);
        }
        [0x00, b'a', b's', b'm'] => return d(Format::Wasm),
        [b'P', b'K', 0x03, 0x04] | [b'P', b'K', 0x05, 0x06] => return d(classify_zip(bytes)),
        [0xd0, 0xcf, 0x11, 0xe0] if bytes.get(4..8) == Some(&[0xa1, 0xb1, 0x1a, 0xe1]) => {
            return d(Format::Ole);
        }
        _ => {}
    }
    if bytes.starts_with(b"%PDF-") {
        return d(Format::Pdf);
    }
    if bytes.len() >= 8
        && &bytes[..4] == b"dex\n"
        && bytes[4..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == 0
    {
        return d(Format::Dex);
    }
    if bytes.starts_with(b"!<arch>\n") {
        return d(Format::Archive);
    }
    if bytes.starts_with(b"MZ") {
        if let Some(lfanew) = le32(bytes, 0x3c)
            && bytes.get(lfanew as usize..(lfanew as usize).saturating_add(4)) == Some(b"PE\0\0")
        {
            return d(if pe_is_dotnet(bytes, lfanew as usize) {
                Format::PeDotnet
            } else {
                Format::Pe
            });
        }
        return d(Format::Unknown);
    }
    if is_asar(bytes) {
        return d(Format::Asar);
    }
    d(Format::Unknown)
}

/// .NET if data directory 14 (CLR runtime header) is non-zero.
fn pe_is_dotnet(b: &[u8], lfanew: usize) -> bool {
    let opt = lfanew + 24;
    let Some(magic) = le16(b, opt) else {
        return false;
    };
    let dd = match magic {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return false,
    };
    let num = le32(b, if magic == 0x10b { opt + 92 } else { opt + 108 }).unwrap_or(0);
    if num <= 14 {
        return false;
    }
    let e = dd + 14 * 8;
    matches!((le32(b, e), le32(b, e + 4)), (Some(rva), Some(sz)) if rva != 0 && sz != 0)
}

/// Electron `app.asar`: Chromium pickle header followed by a JSON file table.
fn is_asar(b: &[u8]) -> bool {
    le32(b, 0) == Some(4) && b.get(16..25) == Some(br#"{"files":"#)
}

fn classify_zip(bytes: &[u8]) -> Format {
    let Ok(z) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return Format::Zip;
    };
    let mut manifest = false;
    let mut dex = false;
    let mut payload_app = false;
    let mut meta_manifest = false;
    let mut class = false;
    let mut content_types = false;
    for name in z.file_names().flatten() {
        let name: &str = &name;
        match name {
            "AndroidManifest.xml" => manifest = true,
            "META-INF/MANIFEST.MF" => meta_manifest = true,
            "[Content_Types].xml" => content_types = true,
            _ => {}
        }
        if name.starts_with("classes") && name.ends_with(".dex") && !name.contains('/') {
            dex = true;
        }
        if name.starts_with("Payload/") && name.contains(".app/") {
            payload_app = true;
        }
        if name.ends_with(".class") {
            class = true;
        }
    }
    if manifest && dex {
        Format::Apk
    } else if payload_app {
        Format::Ipa
    } else if content_types {
        Format::Ooxml
    } else if meta_manifest || class {
        Format::Jar
    } else {
        Format::Zip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_with(names: &[&str]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            for n in names {
                w.start_file(*n, zip::write::SimpleFileOptions::default())
                    .unwrap();
                w.write_all(b"x").unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn magic_formats() {
        assert_eq!(detect(b"\x7fELF\x02\x01").format, Format::Elf);
        assert_eq!(
            detect(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0]).format,
            Format::Macho
        );
        assert_eq!(detect(b"\0asm\x01\0\0\0").format, Format::Wasm);
        assert_eq!(detect(b"%PDF-1.7\n").format, Format::Pdf);
        assert_eq!(detect(b"dex\n035\0rest").format, Format::Dex);
        assert_eq!(
            detect(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).format,
            Format::Ole
        );
        assert_eq!(detect(b"!<arch>\nfoo").format, Format::Archive);
        assert_eq!(detect(b"").format, Format::Unknown);
        assert_eq!(detect(b"MZ").format, Format::Unknown);
    }

    #[test]
    fn cafebabe_disambiguation() {
        // Fat Mach-O with 2 slices.
        assert_eq!(
            detect(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]).format,
            Format::MachoFat
        );
        // Java class: minor 0, major 52 (Java 8).
        assert_eq!(
            detect(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]).format,
            Format::JavaClass
        );
    }

    #[test]
    fn zip_kinds() {
        assert_eq!(
            detect(&zip_with(&["AndroidManifest.xml", "classes.dex"])).format,
            Format::Apk
        );
        assert_eq!(
            detect(&zip_with(&["Payload/Foo.app/Foo"])).format,
            Format::Ipa
        );
        assert_eq!(
            detect(&zip_with(&["META-INF/MANIFEST.MF", "a/B.class"])).format,
            Format::Jar
        );
        assert_eq!(
            detect(&zip_with(&["[Content_Types].xml", "word/document.xml"])).format,
            Format::Ooxml
        );
        assert_eq!(detect(&zip_with(&["readme.txt"])).format, Format::Zip);
    }

    #[test]
    fn asar() {
        let mut b = vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(br#"{"files":{}}"#);
        assert_eq!(detect(&b).format, Format::Asar);
    }

    #[test]
    fn pe_and_dotnet() {
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c] = 0x80;
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let opt = 0x80 + 24;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        assert_eq!(detect(&b).format, Format::Pe);
        let e = opt + 112 + 14 * 8;
        b[e..e + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        b[e + 4..e + 8].copy_from_slice(&0x48u32.to_le_bytes());
        assert_eq!(detect(&b).format, Format::PeDotnet);
    }
}
