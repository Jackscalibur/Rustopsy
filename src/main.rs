mod binary;
mod pdf;

use std::env;
use binary::ELFBinary;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <path-to-elf-binary>", args[0]);
        return;
    }

    match ELFBinary::analyze(&args[1]) {
        Ok(binary) => {
            println!("{}", binary.generate_report());
            
            // Generate PDF report
            let pdf_path = format!("{}.pdf", args[1]);
            match pdf::generate_pdf_report(&binary, &pdf_path) {
                Ok(_) => println!("\nPDF report generated: {}", pdf_path),
                Err(e) => eprintln!("Error generating PDF: {}", e),
            }
        },
        Err(e) => eprintln!("Error analyzing binary: {}", e),
    }
}   
