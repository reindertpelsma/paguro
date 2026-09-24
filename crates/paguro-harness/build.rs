// Compile the kernel module's core (range test, NTFS parser, claim checks)
// into the harness so it can be differential-tested against the Rust
// specification in paguro-core. Warnings are errors, as for the module.
fn main() {
    let dir = "../../kernel/dm-paguro";
    let files = ["pg_range.c", "pg_claim.c", "pg_ntfs.c"];
    for f in files
        .iter()
        .chain(&["pg_range.h", "pg_claim.h", "pg_ntfs.h"])
    {
        println!("cargo:rerun-if-changed={dir}/{f}");
    }
    cc::Build::new()
        .files(files.iter().map(|f| format!("{dir}/{f}")))
        .include(dir)
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .compile("pgcore");
}
