use goblin::{elf::program_header::PT_LOAD, mach::{constants::{VM_PROT_EXECUTE, VM_PROT_WRITE}, cputype::CPU_TYPE_X86}, pe::section_table::{IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE}};
use std::fmt;

// goblin::Object without fat mach
pub enum ImageBinary<'a> {
    PE(goblin::pe::PE<'a>),
    ELF(goblin::elf::Elf<'a>),
    MachO(goblin::mach::MachO<'a>),
    Unknown()
}

pub const IMAGE_FLAGS_PE: usize = 1 << 0;
pub const IMAGE_FLAGS_ELF: usize = 1 << 1;
pub const IMAGE_FLAGS_MACHO: usize = 1 << 2;

pub const IMAGE_FLAGS_64BIT: usize = 1 << 8;

impl ImageBinary<'_> {
    #[must_use]
    pub const fn variant_name(&self) -> &str {
        match &self {
            ImageBinary::ELF(_) => "Elf",
            ImageBinary::PE(_) => "PE",
            ImageBinary::MachO(_) => "MachO",
            ImageBinary::Unknown() => "Other"
        }
    }
}

#[derive(Debug)]
pub struct ImageSection {
    pub name: Option<String>,
    pub file_offset: u64,
    pub size: u64,
    pub virtual_address: u64,
    pub is_writable: bool,
    pub is_code: bool
}

pub struct Image<'a> {
    pub binary: ImageBinary<'a>,
    pub flags: usize,
    pub base: u64,
    pub sections: Vec<ImageSection>
}

impl fmt::Debug for Image<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Image")
            .field("binary.variant_name()", &self.binary.variant_name())
            .field("flags", &self.flags)
            .field("base", &self.base)
            .field("sections", &self.sections)
            .finish()
    }
}

impl Image<'_> {
    #[must_use]
    pub fn from(buffer: &[u8]) -> Option<Image> {
        let binary = match goblin::Object::parse(buffer).ok()? {
            goblin::Object::PE(pe) => ImageBinary::PE(pe),
            goblin::Object::Elf(elf) => ImageBinary::ELF(elf),
            goblin::Object::Mach(mach) => {
                ImageBinary::MachO(match mach {
                    // TODO: user option to specify arch, if necessary
                    goblin::mach::Mach::Fat(fat) => {
                        let index = fat.iter_arches().position(|a| a.is_ok_and(|x| x.cputype & CPU_TYPE_X86 != 0));
                        fat.get(index?).ok()?
                    },
                    goblin::mach::Mach::Binary(bin) => bin
                })
            },
            _ => {
                return None;
            }
        };

        let mut sections: Vec<ImageSection> = Vec::new();
        let mut flags: usize = 0;

        match &binary {
            ImageBinary::PE(pe) => {
                flags |= IMAGE_FLAGS_PE;
                if pe.is_64 {
                    flags |= IMAGE_FLAGS_64BIT;
                }

                for section in &pe.sections {
                    sections.push(ImageSection {
                        name: section.name().ok().map(|s| s.to_string()),
                        file_offset: u64::from(section.pointer_to_raw_data),
                        size: u64::from(section.size_of_raw_data),
                        virtual_address: u64::from(section.virtual_address) + pe.image_base as u64,
                        is_writable: (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0,
                        is_code: (section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) != 0
                    });
                }
            },
            ImageBinary::ELF(elf) => {
                flags |= IMAGE_FLAGS_ELF;
                if elf.is_64 {
                    flags |= IMAGE_FLAGS_64BIT;
                }

                // for now
                if !elf.little_endian {
                    return None;
                }

                for segment in &elf.program_headers {
                    if segment.p_type == PT_LOAD {
                        sections.push(ImageSection {
                            name: Some(format!("PHDR_{:08X}", segment.p_offset)),
                            file_offset: segment.p_offset,
                            size: segment.p_filesz,
                            virtual_address: segment.p_vaddr,
                            is_writable: segment.is_write(),
                            is_code: segment.is_executable()
                        });
                    }
                }
            },
            ImageBinary::MachO(macho) => {
                flags |= IMAGE_FLAGS_MACHO;
                if macho.is_64 {
                    flags |= IMAGE_FLAGS_64BIT;
                }

                // for now
                if !macho.little_endian {
                    return None;
                }

                for segment in &macho.segments {
                    sections.push(ImageSection {
                        name: segment.name().ok().map(|s| s.to_string()),
                        file_offset: segment.fileoff,
                        size: segment.filesize,
                        virtual_address: segment.vmaddr,
                        is_writable: segment.maxprot & VM_PROT_WRITE != 0,
                        is_code: segment.maxprot & VM_PROT_EXECUTE != 0
                    });
                }                
            },
            ImageBinary::Unknown() => {
                return None;
            }
        };

        let base: u64 = match &binary {
            ImageBinary::PE(pe) => pe.image_base as u64,
            _ => 0
        };

        Some(Image {
            binary,
            flags,
            base,
            sections
        })
    }

    pub fn rva2fo(&self, rva: u64) -> Option<u64> {
        self.va2fo(self.base + rva as u64)
    }

    pub fn fo2rva(&self, offset: u64) -> Option<u64> {
        self.fo2va(offset).map(|va| va - self.base)
    }

    pub fn fo2va(&self, offset: u64) -> Option<u64> {
        for section in &self.sections {
            if offset >= section.file_offset && offset < section.file_offset + section.size {
                return Some((offset - section.file_offset) + section.virtual_address)
            }
        }
        None
    }

    pub fn va2fo(&self, va: u64) -> Option<u64> {
        for section in &self.sections {
            if va >= section.virtual_address && va < section.virtual_address + section.size {
                return Some((va - section.virtual_address) + section.file_offset)
            }
        }
        None
    }

    pub fn is_x64(&self) -> bool {
        self.flags & IMAGE_FLAGS_64BIT != 0
    }
}