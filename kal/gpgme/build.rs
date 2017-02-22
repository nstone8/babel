fn main() {
    println!("cargo:rustc-link-lib=dylib=gpgme");
    println!("cargo:rustc-link-search=native=/usr/local/lib");
}
