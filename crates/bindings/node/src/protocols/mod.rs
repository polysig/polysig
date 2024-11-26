#[cfg(feature = "cggmp")]
pub mod cggmp;

#[cfg(feature = "frost")]
pub mod frost;

pub mod meeting;

mod types;

#[napi::module_init]
fn init() {
    use napi::bindgen_prelude::create_custom_tokio_runtime;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .on_thread_start(|| {
            // println!("tokio thread started");
        })
        .build()
        .unwrap();
    create_custom_tokio_runtime(rt);
}
