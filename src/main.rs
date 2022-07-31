use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use core::mem::size_of;
use thiserror::Error;
use widestring::U16Str;

#[derive(Error, Debug)]
pub enum PEError {
    #[error("format not supported: {0}")]
    FormatNotSupported(String),

    #[error("malformed PE file: {0}")]
    MalformedPEFile(String),

    #[error("PE file does not contain a resource table")]
    NoResourceTable(),
}

// struct _IMAGE_RESOURCE_DIRECTORY, winnt.h
#[repr(C)]
struct _ImageResourceDirectory {
    characteristics: u32,         // offset 0
    time_date_stamp: u32,         // offset 4
    major_version: u16,           // offset 8
    minor_version: u16,           // offset 10
    number_of_named_entries: u16, // offset 12
    number_of_id_entries: u16,    // offset 14
                                  //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[]; // offset 16
}

#[repr(C)]
struct _NamedResourceEntry {
    name: u32, // high-bit: 1, bits 0-31: offset
}

#[repr(C)]
struct _IdResourceEntry {
    unused: u16,
    id: u16,
}

#[repr(C)]
struct _DataDirectoryEntry {
    offset: u32, // high-bit: 0, bits 0-31: offset
}

#[repr(C)]
struct _SubDirectoryEntry {
    offset: u32, // high-bit: 1, bits 0-31: offset to another _ImageResourceDirectoryEntry
}

// struct _IMAGE_RESOURCE_DIRECTORY_ENTRY, winnt.h
#[repr(C)]
struct _ImageResourceDirectoryEntry {
    u1: _NamedResourceEntry, // union _NamedResourceEntry / _IdResourceEntry
    u2: _DataDirectoryEntry, // union _DataDirectoryEntry / _SubDirectoryEntry
}

// struct _IMAGE_RESOURCE_DATA_ENTRY, winnt.h
#[repr(C)]
struct _ImageResourceDataEntry {
    offset_to_data: u32, // offset 0
    size: u32,           // offset 4
    code_page: u32,      // offset 8
    _reserved: u32,      // offset 12
}

// struct _IMAGE_RESOURCE_DIRECTORY_ENTRY, winnt.h
#[derive(Debug, Clone)]
struct ImageResourceDirectoryEntry {
    _id: ResourceIdType,
    _code_page: u32,
    rva_to_data: usize, // relative to the start of the PE
    data_size: usize,
}

#[derive(Debug, PartialEq, Clone)]
enum ResourceIdType {
    Name(String),
    Id(u16),
}

// Compare "#012" as 0n12, as described in the MSDN documentation for FindResource.
// Any string parse errors return false.
fn compare_str_id(name: &str, id: &u16) -> bool {
    if name.chars().nth(0).unwrap_or('x') == '#' {
        let parsed_id = name.get(1..).unwrap().parse::<u16>();
        if parsed_id.is_ok() {
            return parsed_id.unwrap() == *id;
        }
    }
    false
}

impl PartialEq<&str> for ResourceIdType {
    fn eq(&self, name: &&str) -> bool {
        match self {
            ResourceIdType::Name(x) => x == name,
            ResourceIdType::Id(id) => compare_str_id(name, id),
        }
    }
}

impl PartialEq<u16> for ResourceIdType {
    fn eq(&self, id: &u16) -> bool {
        match self {
            ResourceIdType::Id(x) => *x == *id,
            ResourceIdType::Name(name) => compare_str_id(name, id),
        }
    }
}

#[derive(Debug)]
struct ImageResourceDirectoryRoot {
    id: ResourceIdType,
    sub_directories: Vec<ImageResourceEntry>,
}

#[derive(Debug)]
enum ImageResourceEntry {
    Directory(ImageResourceDirectoryRoot),
    Data(ImageResourceDirectoryEntry),
}

impl ImageResourceEntry {
    // fn read_u8(buf: &'a [u8], offset: usize) -> u8 {
    //     // TODO: bounds check
    //     buf[offset]
    // }

    fn read_u16(buf: &[u8], offset: usize) -> u16 {
        // TODO: bounds check
        let _buf = &buf[offset..offset + 2];
        LittleEndian::read_u16(_buf)
    }

    fn read_u32(buf: &[u8], offset: usize) -> u32 {
        // TODO: bounds check
        let _buf = &buf[offset..offset + 4];
        LittleEndian::read_u32(_buf)
    }

    unsafe fn read_counted_str(buf: &[u8], offset: usize) -> &U16Str {
        // TODO: bounds check
        let cch = Self::read_u16(buf, offset) as usize;
        let str = &buf[offset + 2] as *const u8 as *const u16;
        U16Str::from_ptr(str, cch)
    }

    fn parse(
        buf: &[u8],
        directory_offset: usize,
        directory_id: ResourceIdType,
    ) -> ImageResourceEntry {
        let num_named_entries = ImageResourceEntry::read_u16(buf, directory_offset + 12);
        let num_id_entries = ImageResourceEntry::read_u16(buf, directory_offset + 14);
        let mut entries = Vec::with_capacity(num_named_entries as usize + num_id_entries as usize);
        let mut offset = directory_offset + size_of::<_ImageResourceDirectory>() as usize;

        for i in 0..num_named_entries + num_id_entries {
            offset = offset + size_of::<_ImageResourceDirectoryEntry>() * i as usize;
            let u1 = Self::read_u32(buf, offset); // _NamedResourceEntry / _IdResourceEntry
            assert!(size_of::<_NamedResourceEntry>() == size_of::<u32>());
            let u2 = Self::read_u32(buf, offset + size_of::<_NamedResourceEntry>()); // _DataDirectoryEntry / _SubDirectoryEntry

            let id = if u1 & 0x8000_0000 != 0 {
                // entry is a _NamedResourceEntry

                let name_offset = u1 & 0x7FFF_FFFF;
                unsafe {
                    let name = Self::read_counted_str(buf, name_offset as usize);
                    ResourceIdType::Name(name.to_string().unwrap())
                }
            } else {
                // entry is a _IdResourceEntry
                ResourceIdType::Id(u1 as u16)
            };

            if u2 & 0x8000_0000 == 0 {
                // entry is not a subdirectory
                let offset_to_data_entry = u2 as usize;

                // RVA is relative to the start of the PE, not the start of the current directory
                let rva_to_data = Self::read_u32(buf, offset_to_data_entry) as usize;
                let data_size = Self::read_u32(buf, offset_to_data_entry + 4) as usize;
                // this is probably wrong?
                let code_page = Self::read_u32(buf, offset_to_data_entry + 8);

                entries.push(ImageResourceEntry::Data(ImageResourceDirectoryEntry {
                    _id: id,
                    _code_page: code_page,
                    rva_to_data,
                    data_size,
                }));
            } else {
                // entry is another directory
                let offset_to_subdirectory_entry = (u2 & 0x7FFF_FFFF) as usize;
                let subdirectory = Self::parse(&buf, offset_to_subdirectory_entry, id);

                entries.push(subdirectory);
            }
        }

        ImageResourceEntry::Directory(ImageResourceDirectoryRoot {
            id: directory_id,
            sub_directories: entries,
        })
    }

    // Win32 FindResourceW
    fn find<T, U>(&self, name: &T, id: &U) -> Option<ImageResourceDirectoryEntry>
    where
        ResourceIdType: PartialEq<T>,
        ResourceIdType: PartialEq<U>,
    {
        match self {
            ImageResourceEntry::Directory(root) => {
                for item in root.sub_directories.iter() {
                    if let ImageResourceEntry::Directory(dir) = item {
                        if dir.id == *name {
                            let x = dir.sub_directories.iter().find(|subdir| {
                                if let ImageResourceEntry::Directory(child) = subdir {
                                    if child.id == *id {
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            });
                            if let Some(ImageResourceEntry::Directory(found_dir)) = x {
                                match found_dir.sub_directories.first().unwrap() {
                                    ImageResourceEntry::Data(data) => return Some(data.clone()),
                                    _ => return None,
                                }
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }
}

fn main() -> Result<()> {
    let matches = clap::App::new("rsrc")
        .arg(
            clap::Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("log verbose messages"),
        )
        .arg(
            clap::Arg::with_name("input")
                .required(true)
                .index(1)
                .help("path to input PE file"),
        )
        .get_matches();

    let filename = matches.value_of("input").unwrap();
    let buf = std::fs::read(filename)?;
    if buf.len() < 0x10 {
        panic!("file too small: {}", filename);
    }

    let _pe: Result<goblin::pe::PE, PEError> = match goblin::Object::parse(&buf)? {
        goblin::Object::PE(pe) => {
            if let Some(opt) = pe.header.optional_header {
                if opt.data_directories.get_clr_runtime_header().is_some() {
                    return Err(PEError::FormatNotSupported(".NET assembly".to_string()).into());
                }
            }
            Ok(pe)
        }
        goblin::Object::Elf(_) => Err(PEError::FormatNotSupported("elf".to_string()).into()),
        goblin::Object::Archive(_) => {
            Err(PEError::FormatNotSupported("archive".to_string()).into())
        }
        goblin::Object::Mach(_) => Err(PEError::FormatNotSupported("macho".to_string()).into()),
        goblin::Object::Unknown(_) => {
            Err(PEError::FormatNotSupported("unknown".to_string()).into())
        }
    };

    let pe = _pe?;

    // for section in pe?.sections {
    //     let section_name = String::from_utf8_lossy(&section.name[..])
    //         .into_owned()
    //         .trim_end_matches('\u{0}')
    //         .trim_end()
    //         .splitn(2, '\u{0}')
    //         .next()
    //         .unwrap();
    // }

    let optional_header = pe.header.optional_header.unwrap();

    let resource_table = match optional_header.data_directories.get_resource_table() {
        None => Err(PEError::NoResourceTable()),
        Some(t) => Ok(t),
    }?;

    let resource_table_start = resource_table.virtual_address as usize;
    let resource_table_end = resource_table_start + resource_table.size as usize;

    let mut resource_section: Option<goblin::pe::section_table::SectionTable> = None;

    // PE section names are mostly meaningless, so looking for the ".rsrc" section by name may not work
    for section in pe.sections {
        if section.virtual_address as usize >= resource_table_start
            && (section.virtual_address + section.virtual_size) as usize <= resource_table_end
        {
            resource_section = Some(section);
            break;
        }
    }

    let resource_section_table =
        resource_section.expect("could not find section that holds the resource table");

    // offset will almost always == resource_section_table.pointer_to_raw_data,
    // because the resource table will start will start exactly at the start of the section
    let offset = resource_table_start - resource_section_table.virtual_address as usize
        + resource_section_table.pointer_to_raw_data as usize;
    let end = offset + resource_section_table.virtual_size as usize;
    let section_name = resource_section_table.name()?;

    let resources = ImageResourceEntry::parse(
        &buf[offset..end],
        0,
        ResourceIdType::Name(section_name.to_string()),
    );

    let pmres_data2 = resources.find(&"WEVT_TEMPLATE", &"#1");
    let pmres_resource_data = pmres_data2.ok_or(PEError::NoResourceTable())?;

    let rva_to_va_offset = (resource_section_table.virtual_address
        - resource_section_table.pointer_to_raw_data) as usize;
    let pmres = &buf[pmres_resource_data.rva_to_data - rva_to_va_offset
        ..pmres_resource_data.rva_to_data - rva_to_va_offset + pmres_resource_data.data_size];

    println!("pmres header: {:?}", std::str::from_utf8(&pmres[0..4])?);

    Ok(())
}
