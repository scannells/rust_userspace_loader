#![feature(asm)]

mod load_elf;
mod parse_elf;
mod stack_setup;

fn main() {

    // ensure that there is at least one argument to this program, it is the program that should be loaded
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        panic!("Usage: {} /PATH/TO/PROGRAM/TO/LOAD", args[0]);
    }

    // parse the ELF file to be loaded to obtain necessary load information
    let binary_info = parse_elf::parse_elf(&args[1]);

    // we will have to check if the ELF file uses an interpreter. If so, the entry point needs to be _start of that shared object file (usually ld.so)
    let (entry_point, interp_base) = if let Some(elf_interp) = &binary_info.elf_interp {
                        let loader_info = parse_elf::parse_elf(elf_interp);
                        let loader_load = load_elf::ElfLoad::load(&loader_info);
                        
                        // the loader is PIE so offsts such as the entry point are relative to its load address. Figure out where the loader will load it 
                        // to ensure we have the correct entry point and base address for the stack
                        (loader_info.entry_point + loader_load.load_addr, loader_load.load_addr)
                    } else {
                        (binary_info.entry_point, 0)
                    };

    // load the binary into memory
    let binary_load = load_elf::ElfLoad::load(&binary_info);

    // setup a new execution stack. The initial stack layout is the same, wether this is a static ELF_EXEC, PIE ELF_DYN or anything else for that matter
    // save the RSP so that we can jump to it later
    let rsp = stack_setup::setup_stack(&binary_info, binary_load.load_addr, interp_base);


    // kick off execution by clearing all registers, switching to the new stack and jumping to the entry point
    unsafe {
        asm!("
            mov rsp, rax
            push rbx

            xor rax, rax
            xor rbx, rbx
            xor rcx, rcx
            xor rdx, rdx
            xor rdi, rdi
            xor rsi, rsi

            xor r9, r9
            xor r10, r10
            xor r11, r11
            xor r12, r12
            xor r13, r13
            xor r14, r14
            xor r15, r15

            ret
            ",
            in("rax") rsp,
            in("rbx") entry_point
        );
    }


}