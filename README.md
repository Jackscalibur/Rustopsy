# Rustopsy

Rustopsy is a Rust-based binary analysis tool designed to analyze ELF binaries and evaluate their security features. It provides insights into various security mechanisms implemented in the binary and generates detailed reports, including a PDF summary.

## Features

- **Architecture Detection**: Identifies the architecture of the ELF binary (e.g., x86_64, ARM, AARCH64).
- **Security Feature Analysis**:
  - RELRO (Read-Only Relocation) status.
  - PIE (Position Independent Executable) status.
  - NX (No eXecute) status.
  - Stack Canary status.
  - FORTIFY_SOURCE status.
- **Security Scoring**: Calculates a security score (0-10) based on the presence of security features.
- **Report Generation**:
  - Text-based analysis report.
  - PDF report summarizing the analysis.

## Installation

To use Rustopsy, ensure you have Rust installed. You can install Rust using [rustup](https://rustup.rs/).

Clone the repository and build the project:

```bash
git clone <repository-url>
cd Rustopsy
cargo build --release
```

## Usage

Run Rustopsy from the command line to analyze an ELF binary:

```bash
./target/release/rustopsy <path-to-elf-binary> [--verbose]
```

### Example

```bash
./target/release/rustopsy /path/to/binary --verbose
```

- The `--verbose` flag enables detailed output during the analysis.
- A PDF report will be generated in the same directory as the binary, with the `.pdf` extension.

## Dependencies

Rustopsy uses the following crates:

- [`goblin`](https://crates.io/crates/goblin): For parsing ELF binaries.
- [`thiserror`](https://crates.io/crates/thiserror): For error handling.
- [`printpdf`](https://crates.io/crates/printpdf): For generating PDF reports.

## Project Structure

- `src/binary.rs`: Contains the logic for analyzing ELF binaries and extracting security features.
- `src/pdf.rs`: Handles the generation of PDF reports summarizing the analysis.
- `src/main.rs`: Entry point for the application, handles CLI arguments and orchestrates the analysis and report generation.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests to improve the project.

## Acknowledgments

Special thanks to the authors of the `goblin`, `thiserror`, and `printpdf` crates for their excellent libraries that made this project possible.
