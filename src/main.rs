mod parser;
mod stats;

use parser::{ParseOutcome, parse_line};
use stats::{count_by_ip, count_by_user};
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <log_file_path>", args[0]);
        eprintln!("Example: cargo run -- samples/auth_sample.log");
        std::process::exit(1);
    }

    let filepath = &args[1];

    let content = match fs::read_to_string(filepath) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: cannot read file '{}': {}", filepath, e);
            std::process::exit(1);
        }
    };

    let mut failed_logins = Vec::new();
    let mut ignored_count = 0usize;
    let mut malformed_count = 0usize;
    let total_lines = content.lines().count();

    for line in content.lines() {
        match parse_line(line) {
            ParseOutcome::Failed(event) => failed_logins.push(event),
            ParseOutcome::Ignored => ignored_count += 1,
            ParseOutcome::Malformed => malformed_count += 1,
        }
    }

    let top_ips = count_by_ip(&failed_logins);
    let top_users = count_by_user(&failed_logins);

    println!("TP1 Secure Log Analyzer");
    println!("Input file: {}", filepath);
    println!();
    println!("Summary:");
    println!("  - Total lines read:          {}", total_lines);
    println!("  - Failed login events:        {}", failed_logins.len());
    println!(
        "  - Ignored or malformed lines: {}",
        ignored_count + malformed_count
    );
    println!();
    println!("Top source IPs:");
    for (i, (ip, count)) in top_ips.iter().enumerate() {
        let word = if *count == 1 { "attempt" } else { "attempts" };
        println!("  {}. {} -> {} failed {}", i + 1, ip, count, word);
    }
    println!();
    println!("Top targeted users:");
    for (i, (user, count)) in top_users.iter().enumerate() {
        let word = if *count == 1 { "attempt" } else { "attempts" };
        println!("  {}. {} -> {} failed {}", i + 1, user, count, word);
    }
}
