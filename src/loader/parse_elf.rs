use std::io::prelude::*;
use std::fs::File;

use crate::load_elf::ElfSegment;

/// value for a PT_LOAD program header type
const PT_LOAD: u32 = 0x01;

/// value for a PT_INTERP (ELF Interpreter) program header type
const PT_INTERP: u32 = 0x03;

/// standard size of a 64bit ELF header
const SIZE_OF_ELF_HDR: usize = 64;

/// standard size of a program header entry
const SIZE_OF_PROGRAM_HDR: u16 = 56;

/// the value of the e_ident[EI_CLASS] field for a 64bit ELF
const CLASS_64_BIT: u8 = 0x2;

/// the value for the ELF_EXEC type for the ELF type field
const ELF_EXEC: u16 = 0x02;

/// the value for the ELF_DYN type for the ELF type field
const ELF_DYN: u16 = 0x03;


/// the value for Linux ABI for the OS_ABI field
const LINUX_ABI: u8 = 0x3;
/// the value for System-V ABI for the OS_ABI field
const SYSTEMV_ABI: u8 = 0x0;

/// the value for x86 architecture for the machine field
const X86_MACHINE: u16 = 0x3;

/// the value for amd64 architecture for the machine field
const AMD64_MACHINE: u16 = 0x3e;



/// Represents an Elf64_Phdr as found in an actual ELF file
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Elf64Phdr {
    pub ptype:  u32,
    pub pflags: u32,
    pub offset: u64,
    pub vaddr:  u64,
    pub paddr:  u64,
    pub filesz: u64,
    pub memsz:  u64,
    pub align:  u64
}

/// Represents an ELF Header
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct ElfHdr {
    magic:              u32,
    class:              u8,
    endian:             u8,
    elf_version:        u8,
    os_abi:             u8,
    abi_version:        u8,
    padding:            [u8; 7],
    etype:              u16,
    machine:            u16,
    version2:           u32,
    entry_point:        u64,
    program_headers:    u64,
    section_table_off:  u64,
    flags:              u32,
    header_size:        u16,
    pheader_size:       u16,
    pheader_num:        u16,
    shent_size:         u16,
    shnum:              u16,
    shstrnidx:          u16
}



impl ElfHdr {

    /// Takes in a raw u8 buffer of the ELF file to parse and performs checks on it
    pub fn parse(buffer: &[u8]) -> Self {

        // Verify that the buffer is big enough to contain a header
        assert!(SIZE_OF_ELF_HDR <= buffer.len(), "the file is too small to contain an ELF header");
        
        // Copy the buffer into a sized array, otherwise rustc will complain
        let mut buffer_clone: [u8; SIZE_OF_ELF_HDR] = [0; SIZE_OF_ELF_HDR];
        buffer_clone.copy_from_slice(&buffer[..SIZE_OF_ELF_HDR]);

        // now transmute the buffer into an ELF struct and return it
        unsafe {
            std::mem::transmute(buffer_clone)
        }
    }

    /// Throws assertions incase of anything being off (not an ELF header, not an executable, incompatible architecture etc)
    pub fn verify(&self) {
        
        // check the ELF header
        assert!(u32::from_be(self.magic) == 0x7f454c46, "No ELF magic header was found in the target file");

        // ensure that this is a 64 bit binary
        assert!(self.class == CLASS_64_BIT, "At this point, only 64b-it ELF are supported! :(");

        // ensure that this is either an ELF_EXEC or ELF_DYN
        assert!(self.etype == ELF_EXEC || self.etype == ELF_DYN, "At this point, only statically linked executables are supported :(");

        // ensure this ELF is for a supported OS
        assert!(self.os_abi == LINUX_ABI || self.os_abi == SYSTEMV_ABI, "At this point, only the Linux and System-V ABIs are supported :(");

        // ensure the architecture is x86
        assert!(self.machine == X86_MACHINE || self.machine == AMD64_MACHINE, "At this point, only x86-64 ELF's are supported :(");

        // ensure that the program header size is standardized. We don't have time for some fancy non-standard ELFs
        assert!(self.pheader_size == SIZE_OF_PROGRAM_HDR, "This ELF binary's Program Header Entry size differs from the standard Elf64_Phdr size :(");
    }

    /// Parse all PT_LOAD segments into a Vector ElfSegment's. These structs are used by the actual loader to
    /// load the ELF and start it! Also, return the file path of the ELF interpreter used by this application
    pub fn parse_segments(&self, buffer: &[u8]) -> (Option<String>, Vec<ElfSegment>) {
        let mut current_offset = self.program_headers as usize;

        // verify that the current offset + all program headers are in bounds of the buffer representing the ELF file
        let max_offset = current_offset.checked_add((self.pheader_num * self.pheader_size) as usize).unwrap() as usize;
        assert!((max_offset) < buffer.len());

        let mut elf_interp: Option<String> = None;
        let mut res: Vec<ElfSegment> = Vec::new();

        // iterate over each of the program headers and use transmute to get a parsed program header, which in turn will be 
        // turned into a nice and safe Rust struct
        while current_offset < max_offset {
            // Copy the current slice of the buffer into a fixed size array with the size of a program header
            let mut buffer_clone: [u8; SIZE_OF_PROGRAM_HDR as usize] = [0; SIZE_OF_PROGRAM_HDR as usize];
            buffer_clone.copy_from_slice(&buffer[current_offset..current_offset + SIZE_OF_PROGRAM_HDR as usize]);

            // then transmute
            let program_header: Elf64Phdr = unsafe {
                std::mem::transmute(buffer_clone)
            };


            // Only parse this segment if it is loadable or an ELF interpreter
            if program_header.ptype == PT_LOAD || program_header.ptype == PT_INTERP {
                // if this program type is a loadable segment, add it to the list of segments returned here
                // otherwise interpret the contents of the section as a String that contains the path to the ELF interpreter 
                // of this file
                if program_header.ptype == PT_LOAD {
                    let offset = program_header.offset as usize - (program_header.vaddr as usize & (0x1000 -1));
                    let end_offset = offset.checked_add(program_header.filesz as usize + (program_header.vaddr as usize & (0x1000 -1))).unwrap();
                    assert!(end_offset < buffer.len());

                    res.push(
                        ElfSegment::new(&program_header, buffer[offset..end_offset].to_vec())
                    );
                } else {
                    // if this is an interpreter segment, interpret the offset as "absolute" offset
                    // and read the filename (-1) since it contains a NULL byte that RUST does not want to deal
                    // with
                    let offset = program_header.offset as usize;
                    elf_interp = Some(
                        String::from_utf8(buffer[offset..(offset + program_header.filesz as usize - 1)].to_vec()).expect("INTERP segment contains invalid filename")
                    );
                }

            }

            current_offset += SIZE_OF_PROGRAM_HDR as usize;
        }

        (elf_interp, res)
    }
}


pub enum ElfType {
    ElfExec,
    ElfDyn
}

impl ElfType {
    pub fn from(etype: u16) -> Self {
        match etype {
            ELF_EXEC => ElfType::ElfExec,
            ELF_DYN => ElfType::ElfDyn,
            _ => panic!("Invalid ELF type")
        }
    }
}

/// Holds all information the loader needs to set up the binary!
pub struct LoadInfo {
    pub entry_point: usize,
    pub pheader_off: usize,
    pub pheader_num: usize,
    pub segments: Vec<ElfSegment>,
    pub elf_interp: Option<String>,
    pub etype: ElfType,
}



/// Parses an ELF file and performs checks on it, such as verify the architecture, that is an executable and that it is 64bit.
/// It then returns all necessary information needed by the loader (entry point and LOAD segments)
pub fn parse_elf(file: &str) -> LoadInfo {
    let mut elf_file = File::open(file).expect("Could not find file");
    
    // read the file into a dynamic sized buffer
    let mut buffer = Vec::new();
    elf_file.read_to_end(&mut buffer).expect("Could not read ELF file!");
    let buffer = buffer;

    // make sure this is a valid ELF and prepare to parse
    let hdr = ElfHdr::parse(&buffer);
    hdr.verify();


    // parse all the loadable segments

    // parse the segments and pass them to the loader, as well as all necessary information
    //(hdr.program_headers as usize, hdr.entry_point as usize, hdr.parse_segments(&buffer))
    let (elf_interp, segments) = hdr.parse_segments(&buffer);
    LoadInfo {
        entry_point: hdr.entry_point as usize,
        pheader_off: hdr.program_headers as usize,
        pheader_num: hdr.pheader_num as usize,
        segments: segments,
        elf_interp: elf_interp,
        etype: ElfType::from(hdr.etype)
    }
}

