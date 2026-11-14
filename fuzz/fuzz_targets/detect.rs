#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = drishti_loader::detect(data);
    let _ = drishti_loader::zip_children(data, 100);
    let _ = drishti_loader::asar_children(data, 100);
});
