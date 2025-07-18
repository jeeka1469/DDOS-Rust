use std::env;
use std::path::Path;

fn main() {
    // Change this path to your Npcap SDK installation folder if different
    let npcap_sdk_lib = r"C:\Npcap-SDK\Lib\x64";

    // Tell Rust linker where to find the libs
    println!("cargo:rustc-link-search=native={}", npcap_sdk_lib);

    // Tell linker to link with Packet.lib
    println!("cargo:rustc-link-lib=static=Packet");

    // (Optional) if you want to link with wpcap.lib as well
    println!("cargo:rustc-link-lib=dylib=wpcap");

    // To rerun build script if something changes (optional)
    println!("cargo:rerun-if-changed=build.rs");
}
