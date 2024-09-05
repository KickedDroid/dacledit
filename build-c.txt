use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir);

    // Compile C code
    cc::Build::new()
        .file("lib/dacledit.c")
        .flag("-fPIC")
        .include("/usr/include")
        .compile("dacledit");

    // Link against required libraries
    println!("cargo:rustc-link-lib=ldap");
    println!("cargo:rustc-link-lib=lber");
    println!("cargo:rustc-link-lib=krb5");
    println!("cargo:rustc-link-lib=gssapi_krb5");
    // Tell cargo to invalidate the built crate whenever the C file changes
    println!("cargo:rerun-if-changed=dacledit.c");
    // THis is not working for some reason 
}