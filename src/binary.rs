use goblin::Object;
use std::fs::File;
use std::io::{self, Read};

pub fn get_binary_architecture(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let arch = match Object::parse(&buffer).unwrap() {
        Object::Elf(elf) => format!("ELF - {:?}", elf.header.e_machine),
        _ => "Unknown binary format".to_string(),
    };

    Ok(arch)
}