fn main() {

    let npcap_sdk_lib = r"C:\Npcap-SDK\Lib\x64";

    println!("cargo:rustc-link-search=native={npcap_sdk_lib}");

    println!("cargo:rustc-link-lib=static=Packet");

    println!("cargo:rustc-link-lib=dylib=wpcap");

    println!("cargo:rerun-if-changed=build.rs");
}
