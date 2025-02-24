use goblin::elf::Elf;
use std::fs::File;
use std::io::{self, Read};

// TODO: Relro status, PIE status, NX status, Stack Canary status, FORTIFY_SOURCE status, etc

#[derive(Debug)]
pub struct ELFBinary {
    pub path: String,
    pub architecture: String,
    pub relro: String,
    pub pie: String,
    pub nx: String,
    pub canary: String,
    pub fortify_source: String,
}

impl ELFBinary {
    pub fn architecture_from_file(path: &str) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = Elf::parse(&buffer).map_err(|e| io:Error::new(io::ErrorKind::InvalidData, e))?;

        let architecture = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64",
            // ...
        }
        .to_string();

        Ok(Self {
            path: path.to_string(),
            architecture,
            relro,
            pie,
            nx,
            canary,
            fortify_source,
        })
    }
}