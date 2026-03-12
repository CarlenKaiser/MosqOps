fn main() {
    println!("cargo:rustc-link-lib=mosquitto");
    println!("cargo:rustc-link-lib=cjson");
}
