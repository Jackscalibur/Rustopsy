mod binary;

fn main() {
    println!("Welcome to Rustopsy!");

    let bin_arch = binary::get_binary_architecture("src/main.rs").unwrap();
    println!("Binary architecture: {}", bin_arch);

    // TODO: Add usage instructions
}   
