// `sqlx::migrate!()` embeds `migrations/` at compile time, and cargo does not
// see that directory on its own: a migration added without a Rust change would
// ship in a binary that lacks it.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
