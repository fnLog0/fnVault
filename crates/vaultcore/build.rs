fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/keychain_shim.m")
            .flag("-fobjc-arc")
            .flag("-Wno-deprecated-declarations")
            .compile("fnvault_shim");

        println!("cargo:rerun-if-changed=src/keychain_shim.m");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=AppKit");
    }
}
