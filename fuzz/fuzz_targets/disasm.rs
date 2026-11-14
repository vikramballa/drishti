#![no_main]
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let blob = Arc::new(drishti_loader::Blob::from_vec(data.to_vec()));
    if let Ok(img) = drishti_loader::load_image(blob, None) {
        let opts = drishti_disasm::Options { max_functions: 2000, max_insns_per_function: 20_000, ..Default::default() };
        if let Ok(a) = drishti_disasm::analyze(&img, &opts, &|_| {}, &AtomicBool::new(false)) {
            let _ = drishti_disasm::insights::behaviors(&img, Some(&a));
            if let Some(f) = a.functions.first() {
                let _ = a.cfg(&img, f.entry);
                let _ = drishti_disasm::diff::fingerprint(&img, f);
            }
        }
    }
});
