
use core::ffi::c_void;

extern crate rand;
use rand::Rng;

extern crate nix;
use nix::sys::mman::{
    mmap,
    ProtFlags,
    MapFlags
};

extern crate libc;

use crate::parse_elf::{
    LoadInfo,
    ElfType
};



/// ELFAux IDs and values
const AT_SYSINFO_EHDR: u64 = 33;
const AT_HWCAP: u64 =   16;
const AT_PAGESZ: u64 =  6;
const AT_CLKTCK: u64 =  17;
const AT_PHDR: u64 =    3;
const AT_PHENT: u64 =   4;
const AT_PHNUM: u64 =   5;
const AT_BASE: u64 =   7;
const AT_FLAGS: u64 =   8;
const AT_ENTRY: u64 =   9;
const AT_UID: u64 =   11;
const AT_EUID: u64 =   12;
const AT_GID: u64 =   13;
const AT_EGID: u64 =   14;
const AT_SECURE: u64 =   23;
const AT_RANDOM: u64 =   25;
const AT_HWCAP2: u64 =   26;
const AT_EXECFN: u64 =   31;
const AT_NULL: u64 =   0;


/// the standard size of a program header and the only one we support
const PHENT_SIZE: usize = 0x38;


/// sets up an initial stack according to the System-V x86 ABI and passes information such
/// as the entry point and location of the program headers of the application to tbe loaded
/// to the ELF Interpreter or the CSU routines.
pub fn setup_stack(load_info: &LoadInfo, load_address: usize, interp_base: usize) -> usize {
    // create a new stack for the application and set it up just like the kernel does

    // first, allocate the new stack area and give it 256KB of memory (just a random value I chose)
    let stack_flags = {
        let mut map_flags = MapFlags::empty();
        map_flags.insert(MapFlags::MAP_PRIVATE);
        map_flags.insert(MapFlags::MAP_ANONYMOUS);
        map_flags.insert(MapFlags::MAP_STACK);

        map_flags
    };


    let stack_prot = {
        let mut prot_flags = ProtFlags::empty();
        prot_flags.insert(ProtFlags::PROT_WRITE);
        prot_flags.insert(ProtFlags::PROT_READ);

        prot_flags
    };

    let stack_size = 1024 * 256;
    let stack_end = unsafe {
        mmap(0 as *mut c_void, stack_size, stack_prot, stack_flags, -1, 0)
            .expect("Failed to allocate stack!")
    };

    // the stack grows downward, so setup a stack pointer to the beginnings
    let mut stack_pointer = stack_end as usize + stack_size;

    // 16 byte align the Stack pointer
    stack_pointer = (stack_pointer + 15) & (!15);

    // Copy the current environment onto the stack!
    let mut env: Vec<usize> = Vec::new();
    for (env_name, env_val) in std::env::vars() {
        // format the environment variable as it would actually look like in memory and explicitly add a 0byte
        let env_var = format!("{}={}\0", env_name, env_val);
        stack_pointer -= env_var.len();
        env.push(stack_pointer);
        write_data(stack_pointer, &env_var.as_bytes())
    }

    
    // copy the contents of the program arguments onto the stack and build an argv[] pointer array
    // ignore argv[1], as it is the program to be loaded and is interpreted by this program itself
    let mut argv: Vec<usize> = Vec::new();
    let mut args: Vec<String> = std::env::args().collect();
    args.remove(1);
    for arg in args.iter_mut().rev() {
        stack_pointer -= arg.len() + 1; // +1 for a NULLBYTE
        argv.push(stack_pointer);
        let argv_bytes = unsafe {
            arg.as_mut_vec()
        };
        argv_bytes.push(0); // push a nullbyte
        write_data(stack_pointer, &argv_bytes);
    }


    // after copying the argument contents and environment variables, 16 byte align the stack pointer
    stack_pointer &= !0xf;


    // place the platform string on the stack
    stack_pointer -= "x86_64".len() + 1;
    write_data(stack_pointer, "x86_64\0".as_bytes());
    
    // the next item are 16bytes of random data as a PRNG seed
    let seed_bytes = rand::thread_rng().gen::<[u8; 16]>();
    stack_pointer -= seed_bytes.len();
    write_data(stack_pointer, &seed_bytes);
    let prng_pointer = stack_pointer;

    
    // allocate space for the AUX vectors
    stack_pointer -= 0x120;

    // make space for the argv and envp char ** arrays + a NULL terminator for each of them
    let pointers = (argv.len() + 1) + (env.len() + 1) + 1;
    stack_pointer -= pointers * 8;

    // align the pointer again
    stack_pointer &= !15;

    // the current stack pointer is the one we will return!
    let rsp = stack_pointer;


    // put argc on the stack
    write_pointer(&mut stack_pointer, argv.len());

    // write each of the argument pointers to the stack
    for arg in argv.iter().rev() {
        write_pointer(&mut stack_pointer, *arg);
    }

    // place a NULL pointer to signal this is the end of the argv array
    write_pointer(&mut stack_pointer, 0x0);


    // write each of the environemnt pointers to the stack
    for e in env.iter() {
        write_pointer(&mut stack_pointer, *e);
    }

    // place a NULL pointer to signify that this is the end of the environment pointer
    write_pointer(&mut stack_pointer, 0x0);


        // next are the AUX information needed for the ELF Interpreter and/or __libc_start_main
    // we can derive most of them via libc's getauxval()
    unsafe {

        // VDSO is a shared object mapped into userspace by the kernel that can be used by libc
        write_aux_val(&mut stack_pointer, AT_SYSINFO_EHDR, libc::getauxval(AT_SYSINFO_EHDR));

        // some generic architecture / processor specific value we derive from our own auxvector
        write_aux_val(&mut stack_pointer, AT_HWCAP, libc::getauxval(AT_HWCAP));
        write_aux_val(&mut stack_pointer, AT_PAGESZ, libc::getauxval(AT_PAGESZ));
        write_aux_val(&mut stack_pointer, AT_CLKTCK, libc::getauxval(AT_CLKTCK)); 
        write_aux_val(&mut stack_pointer, AT_HWCAP2, libc::getauxval(AT_HWCAP2));

        // tell the CSU where to find the program headers of the binary to be loaded
        // to do this, we pass a pointer to them, the size of an entry and the number of entries
        write_aux_val(&mut stack_pointer, AT_PHDR, (load_address + load_info.pheader_off) as u64);
        write_aux_val(&mut stack_pointer, AT_PHENT, PHENT_SIZE as u64);
        write_aux_val(&mut stack_pointer, AT_PHNUM, load_info.pheader_num as u64);

        // base is the base address of the ELF Interpreter (ld.so)
        write_aux_val(&mut stack_pointer, AT_BASE, interp_base as u64);

        // the flags are hardcoded 0 by the kernel
        write_aux_val(&mut stack_pointer, AT_FLAGS, 0x0);

        // the entry point of this binary. It is used by (ld.so) to jump to the binary once relocations 
        // have been performed
        // this might be relative or absolute, dependeing on the type of binary that is loaded!
        match load_info.etype {
            ElfType::ElfExec => write_aux_val(&mut stack_pointer, AT_ENTRY, load_info.entry_point as u64),
            ElfType::ElfDyn => write_aux_val(&mut stack_pointer, AT_ENTRY, (load_address + load_info.entry_point) as u64)
        }
        

        // pass some generic info about the user running the process deriving from our own auxval
        write_aux_val(&mut stack_pointer, AT_UID, libc::getauxval(AT_UID));
        write_aux_val(&mut stack_pointer, AT_EUID, libc::getauxval(AT_EUID));
        write_aux_val(&mut stack_pointer, AT_GID, libc::getauxval(AT_GID));
        write_aux_val(&mut stack_pointer, AT_EGID, libc::getauxval(AT_EGID));
        write_aux_val(&mut stack_pointer, AT_SECURE, libc::getauxval(AT_SECURE));

        // pass a pointer to the initial 16 bytes of random memory for use by libc
        write_aux_val(&mut stack_pointer, AT_RANDOM, prng_pointer as u64);
        

        // store a pointer to the program name here
        write_aux_val(&mut stack_pointer, AT_EXECFN, argv[0] as u64);

        // end the aux vector
        write_aux_val(&mut stack_pointer, AT_NULL, 0x0);
    };
    
    // that's it! We should now have a valid and clean stack for executing the new program
    // return the current stack pointer so that we can return it!
    rsp
}



fn write_data(sp: usize, data: &[u8]) {
    unsafe {
        libc::memcpy(sp as *mut c_void, data.as_ptr() as *const c_void, data.len());
    }
}

// writes an AUX val to the stack and advances the stack pointer
fn write_aux_val(sp: &mut usize, aux_id: u64, aux_val: u64) {
   
    write_pointer(sp, aux_id as usize);
    write_pointer(sp, aux_val as usize);

}

fn write_pointer(sp: &mut usize, value: usize) {
    let ptr = *sp as *mut usize;
    unsafe {
        *ptr = value
    };
    *sp += 8;
}