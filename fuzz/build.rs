// The C core, for the ntfs_diff target (C against the Rust specification).
fn main() {
    let dir = "../kernel/dm-paguro";
    for f in [
        "pg_range.c",
        "pg_claim.c",
        "pg_ntfs.c",
        "pg_range.h",
        "pg_claim.h",
        "pg_ntfs.h",
    ] {
        println!("cargo:rerun-if-changed={dir}/{f}");
    }
    cc::Build::new()
        .files(["pg_range.c", "pg_claim.c", "pg_ntfs.c"].map(|f| format!("{dir}/{f}")))
        .include(dir)
        .flag_if_supported("-fsanitize=address,undefined")
        .warnings_into_errors(true)
        .compile("pgcore");
}
