//! Print the script model's score for one file.
//!
//! Used to check the Rust port against the Python model on the same input: the
//! two must agree, because the thresholds were measured with the Python one.

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: score_script <file>");
        std::process::exit(2);
    };
    let data = std::fs::read(&path).expect("read");
    match av_scan::script_model::score(&data) {
        Some(score) => println!("{score:.6}"),
        None => {
            eprintln!("the model did not load");
            std::process::exit(1);
        }
    }
}
