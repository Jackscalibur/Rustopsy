mod binary;
mod pdf;

use std::env;
use binary::ELFBinary;

fn main() {
    // Handle command line arguments and print usage if necessary
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        println!("Usage: {} <path-to-elf-binary> [--verbose]", args[0]);
        return;
    }

    // Check if verbose mode is enabled
    let verbose = args.len() == 3 && args[2] == "--verbose";

    if verbose {
        println!("Verbose mode enabled.");
    }

    // Analyze the ELF binary
    match ELFBinary::analyze(&args[1]) {
        Ok(binary) => {
            if verbose {
                println!("Binary analysis successful.");
            }
            // Print the analysis report
            println!("{}", binary.generate_report());
            
            // Generate PDF report
            let pdf_path = format!("{}.pdf", args[1]);
            if verbose {
                println!("Generating PDF report at: {}", pdf_path);
            }
            match pdf::generate_pdf_report(&binary, &pdf_path) {
                Ok(_) => println!("\nPDF report generated: {}", pdf_path),
                Err(e) => eprintln!("Error generating PDF: {}", e),
            }
        },
        Err(e) => eprintln!("Error analyzing binary: {}", e),
    }
}
