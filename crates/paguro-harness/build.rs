// Compile the kernel module's range logic into the harness so it can be
// differential-tested against the Rust specification (paguro-core::range).
fn main() {
    println!("cargo:rerun-if-changed=../../kernel/dm-paguro/pg_range.c");
    println!("cargo:rerun-if-changed=../../kernel/dm-paguro/pg_range.h");
    cc::Build::new()
        .file("../../kernel/dm-paguro/pg_range.c")
        .include("../../kernel/dm-paguro")
        .warnings(true)
        .extra_warnings(true)
        .compile("pg_range");
}
