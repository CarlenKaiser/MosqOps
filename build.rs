fn main() {
    println!("cargo:rustc-link-search=C:\\mosquitto_devel");
    println!("cargo:rustc-link-lib=mosquitto_broker");
    println!("cargo:rustc-link-lib=mosquitto");
}
