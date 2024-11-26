//! Webassembly bindings for the polysig library.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

/// Threshold signature protocols.
#[cfg(all(
    target_arch = "wasm32",
    target_os = "unknown",
    any(feature = "cggmp", feature = "frost")
))]
pub mod protocols;

/// Single party signers.
#[cfg(all(
    target_arch = "wasm32",
    target_os = "unknown",
    any(feature = "ecdsa", feature = "eddsa", feature = "schnorr")
))]
pub mod signers;

/// Initialize the panic hook and logging.
#[doc(hidden)]
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();

    #[cfg(feature = "tracing")]
    {
        use tracing_subscriber::fmt;
        use tracing_subscriber_wasm::MakeConsoleWriter;
        fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(
                MakeConsoleWriter::default()
                    .map_trace_level_to(tracing::Level::DEBUG),
            )
            // For some reason, if we don't do this
            // in the browser, we get
            // a runtime error.
            .without_time()
            .init();

        log::info!("Webassembly tracing initialized");
    }
}
