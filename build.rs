fn main() {
    // Tell Cargo to recompile when migrations change
    println!("cargo:rerun-if-changed=migrations");
}
