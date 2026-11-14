//! File bytes, memory-mapped so large binaries cost page cache, not heap.

use std::fs::File;
use std::path::Path;

pub enum Blob {
    Mapped(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl std::fmt::Debug for Blob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blob({} bytes)", self.as_ref().len())
    }
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        match self {
            Blob::Mapped(m) => m,
            Blob::Owned(v) => v,
        }
    }
}

impl Blob {
    /// Memory-map `path` read-only. Empty files are held as an empty `Vec`
    /// (mapping zero bytes fails on some platforms).
    pub fn open(path: &Path) -> std::io::Result<Blob> {
        let f = File::open(path)?;
        if f.metadata()?.len() == 0 {
            return Ok(Blob::Owned(Vec::new()));
        }
        // SAFETY: the map is read-only. Drishti analyses files from its own
        // content-addressed store (never modified after write) or files the
        // user points at; if another process truncates such a file while it
        // is mapped, reads may fault, which is the documented memmap2 caveat.
        // We accept that in exchange for not copying multi-GB inputs to heap.
        #[allow(unsafe_code)]
        let m = unsafe { memmap2::Mmap::map(&f)? };
        Ok(Blob::Mapped(m))
    }

    pub fn from_vec(v: Vec<u8>) -> Blob {
        Blob::Owned(v)
    }
}
