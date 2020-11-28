

extern crate nix;
extern crate libc;
use nix::sys::mman::{
    mmap,
    mprotect,
    ProtFlags,
    MapFlags
};
use core::ffi::c_void;


use crate::parse_elf::{Elf64Phdr, LoadInfo, ElfType};

// these values are used to translate ElfPhdr64
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;


const ELF_MIN_ALIGNMENT: usize = 0x1000;
const ELF_MIN_ALIGNMENT_MASK: usize = !(ELF_MIN_ALIGNMENT - 1);



/// represents a PT_LOAD segment of the ELF to be loaded and holds the data to be loaded
#[derive(Debug, Clone)]
pub struct ElfSegment {
    pub virt_addr:  usize,
    pub memsize:    usize,
    pub offset:     usize,
    filesize:       usize,
    alignment:      usize,
    data:           Vec<u8>,
    prot:           ProtFlags,
}



impl ElfSegment {

    /// takes a raw Elf64Phdr as parsed by the parsing module and converts
    /// it into a loadable segment
    pub fn new(hdr: &Elf64Phdr, data: Vec<u8>) -> Self {
        Self {
            virt_addr: hdr.vaddr as usize,
            memsize: hdr.memsz as usize,
            filesize: hdr.filesz as usize,
            alignment: hdr.align as usize,
            data: data,
            offset: hdr.offset as usize,
            prot: Self::get_prot_flags_from_progam_flags(hdr.pflags),
        }
    }

    fn get_prot_flags_from_progam_flags(program_flags: u32) -> ProtFlags {
        let mut prot_flags = ProtFlags::empty();
        if (program_flags & PF_X) != 0 {
            prot_flags.insert(ProtFlags::PROT_EXEC);
        }

        if (program_flags & PF_W) != 0 {
            prot_flags.insert(ProtFlags::PROT_WRITE);
        }

        if (program_flags & PF_R) != 0 {
            prot_flags.insert(ProtFlags::PROT_READ);
        }

        prot_flags
    }
}


/// Statefully emulates the Linux kernel ELF loading logic
pub struct ElfLoad {
    pub load_addr: usize,
}

impl ElfLoad {
    fn get_total_mapping_size(segments: &Vec<ElfSegment>) -> usize {
        let last_idx = segments.len() - 1;

        // logic from the linux kernel
        segments[last_idx].virt_addr + segments[last_idx].memsize - (segments[0].virt_addr & !15)
    }

    pub fn load(load_info: &LoadInfo) -> Self {
        /* There are two types of ELF files:
        *  ET_EXEC and ET_DYN. ET_EXEC are position dependent and are given a load address by the compiler (for gcc it is usually 0x40000)
        *  In the case of such an executable, simply obtain the virtual address of the first PT_LOAD program header and use it as 
        *  an address for a MAP_FIXED mmap() mapping. 

        *  In case of an ET_DYN ELF, the code is position independent and can be loaded anywhere. The Linux kernel usually chooses
        *  0x555555554aaa + ASLR offset. However, since we are already loaded at that address we just let mmap() chose a suitable location
        *  for the new binary. This can be a little awkward as mmap() chooses an address in the 0x7fff... range and might map the file next
        *  to another file. This is awkward because the libc heap uses brk() (the end of the loaded program) to initialize the heap. 
        *  Therefor, we need to set brk() to a safe location where the heap can grow.

        The corresponding Linux kernel code of the following logic is:

        	if (interpreter) {
				load_bias = ELF_ET_DYN_BASE;
				if (current->flags & PF_RANDOMIZE)
					load_bias += arch_mmap_rnd();
				alignment = maximum_alignment(elf_phdata, elf_ex->e_phnum);
				if (alignment)
					load_bias &= ~(alignment - 1);
                elf_flags |= MAP_FIXED;
            else
                load_bias = 0


            The kernel then loads each segment through load_bias + vaddr of section. This way, 
            both static binaries (load bias of 0) that have a set load address and PIE binaries can be loaded with 
            the same logic.
        */

        let segments = &load_info.segments;

        let mut map_flags = MapFlags::empty();
        map_flags.insert(MapFlags::MAP_PRIVATE);
        map_flags.insert(MapFlags::MAP_ANONYMOUS);

        // if the ELF is static, set the MAP_FIXED flag and set the load address to virtual address of the first segment
        // otherwise load at any location (address 0 without MAP_FIXED)
        let mmap_addr = match load_info.etype {
            ElfType::ElfExec => {
                map_flags.insert(MapFlags::MAP_FIXED);
                segments[0].virt_addr - segments[0].offset
            },
            ElfType::ElfDyn => 0
        };

        let map_flags = map_flags;

        // make an allocation large enough for the entire ELF binary, make it read and writable 
        // and populate it with the content. Then change the protection flags for each segment accordingly.
        let total_mapping_size = Self::get_total_mapping_size(&segments);  
        let mut prot_flags = ProtFlags::empty();
        prot_flags.insert(ProtFlags::PROT_READ);
        prot_flags.insert(ProtFlags::PROT_WRITE);
        
        let load_addr = unsafe {
            mmap(mmap_addr as *mut c_void, total_mapping_size, prot_flags, map_flags, -1, 0).expect("Failed to map!")
        };

        // use the load_addr to offset the virt address of each segment. If this is a 
        // static binary, set it to 0 since the virtual addresses in the headers are absolute
        let load_base = if mmap_addr == 0 { 
            load_addr as usize
        } else { 
            0
        };

        // populate the pages of each segment and change the protection status
        for seg in segments.iter() {

            // this is the same logic as in the Linux kernel for aligning addresses of
            // program headers
            let addr = load_base + seg.virt_addr;
            let size = seg.filesize + (addr & (ELF_MIN_ALIGNMENT -1));

            let addr = addr & ELF_MIN_ALIGNMENT_MASK;
            let size = (size + ELF_MIN_ALIGNMENT - 1) & ELF_MIN_ALIGNMENT_MASK;
            
            // copy the actual number of bytes in the file. The (size) might be larger than this
            // as the segment might contain uninitialized data
            unsafe {
                libc::memcpy(addr as *mut c_void, seg.data.as_ptr() as *const c_void, seg.data.len());
            }

            // now change the protection of the segment (with the actual size)
            unsafe {
                mprotect(addr as *mut c_void, size, seg.prot).expect("mprotect() failed");
            }
        }

        ElfLoad {
            load_addr: load_addr as usize,
        }
    }


}
