#![no_main]
// PDF provenance/safety parser: must never panic or hang on hostile input.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = drishti_loader::pdf::analyze(data);
});
