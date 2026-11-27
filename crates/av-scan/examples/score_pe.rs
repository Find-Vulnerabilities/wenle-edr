//! Score one PE with the static model, for sorting a corpus.

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: score_pe <file>");
        std::process::exit(2);
    };
    let data = std::fs::read(&path).expect("read");
    match av_scan::ai::score(&data) {
        Some(score) => println!("{score:.4}"),
        None => {
            println!("not-a-pe");
        }
    }
}
