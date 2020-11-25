use std::process::Command;


fn main() {
    // Compile the dummy binary 
    Command::new("gcc")
        .arg("-o")
        .arg("build/dummy_elf")
        .arg("src/dummy_elf.c")
        .status()
        .expect("failed to execute process");
}