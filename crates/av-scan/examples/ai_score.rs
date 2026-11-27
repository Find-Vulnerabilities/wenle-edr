//! Score one file with the embedded static model.
//!
//! A diagnostic, not a command: `cargo run --release --example ai_score -- <file>`
//! prints the model's probability and the band it lands in, so the Rust port can
//! be compared against the Python model on the same file.

fn main() {
    let path = std::env::args().nth(1).expect("usage: ai_score <file>");
    let data = std::fs::read(&path).expect("the file must be readable");
    match av_scan::ai::score(&data) {
        Some(score) => {
            let band = if score >= av_scan::ai::MALICIOUS_THRESHOLD {
                "malicious"
            } else if score >= av_scan::ai::SUSPICIOUS_THRESHOLD {
                "suspicious"
            } else {
                "clean"
            };
            println!("{score:.4} {band} {path}");
        }
        None => println!("not a PE {path}"),
    }
}
