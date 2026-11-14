#![no_main]
use std::sync::Arc;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let blob = Arc::new(drishti_loader::Blob::from_vec(data.to_vec()));
    let img = drishti_loader::load_image(blob.clone(), None).ok();
    let _ = drishti_loader::file_info(&blob, "f", img.as_ref());
    let strings = drishti_loader::strings(&blob, img.as_ref(), 4, 1000);
    let _ = drishti_loader::insights::iocs(&strings);
    if let Some(img) = img.as_ref() {
        let _ = drishti_loader::insights::hardening(img);
        let _ = drishti_loader::insights::crypto_constants(img);
    }
});
