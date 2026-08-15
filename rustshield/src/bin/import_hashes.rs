// A separate small binary: `cargo run --bin import_hashes -- hashes.csv`
// Reads a CSV of (sha256,threat_name) pairs and loads them into the
// signature database. Point this at a CSV exported from a public feed
// like MalwareBazaar (https://bazaar.abuse.ch/export/) — they publish
// hash lists specifically so tools like this can consume them without
// anyone needing to touch live malware samples.

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[path = "../db.rs"]
mod db;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: import_hashes <path-to-csv>");
        eprintln!("CSV format: sha256,threat_name  (no header row)");
        std::process::exit(1);
    }

    let database =
        db::SignatureDb::open("rustshield_signatures.db").expect("failed to open signature DB");

    let file = File::open(&args[1]).expect("failed to open CSV file");
    let reader = BufReader::new(file);

    let mut count = 0;
    for line in reader.lines() {
        let line = line.expect("read error");
        let parts: Vec<&str> = line.splitn(2, ',').collect();
        if parts.len() != 2 {
            continue;
        }
        let sha256 = parts[0].trim();
        let threat_name = parts[1].trim();

        if database.add_signature(sha256, threat_name, 5).is_ok() {
            count += 1;
        }
    }

    println!("Imported {} signatures.", count);
}
