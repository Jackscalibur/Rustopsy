mod binary;

use std::env;
use binary::ELFBinary;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <path-to-elf-binary>", args[0]);
        return;
    }

    match ELFBinary::analyze(&args[1]) {
        Ok(binary) => println!("{}", binary.generate_report()),
        Err(e) => eprintln!("Error analyzing binary: {}", e),
    }
}   
