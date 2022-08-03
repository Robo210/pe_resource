pub mod rsrc {
    use core::mem::size_of;
    use thiserror::Error;
    use widestring::U16Str;
    use scroll::Pread;

    #[derive(Error, Debug)]
    pub enum PEError {
        #[error("format not supported: {0}")]
        FormatNotSupported(&'static str),

        #[error("malformed PE file: {0}")]
        MalformedPEFile(String),

        #[error("PE file does not contain a resource table")]
        NoResourceTable(),

        #[error("Invalid resource string: {0}")]
        BadResourceString(String),

        #[error("Resource with the provided name / ID not found")]
        ResourceNameNotFound(),

        #[error("An error was returned when prasing the PE: {0}")]
        GoblinError(goblin::error::Error)
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
        // IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[]; // offset 16
    }

    #[repr(C)]
    #[derive(Pread)]
    struct _NamedResourceEntry {
        name: u32, // high-bit: 1, bits 0-31: offset
    }

    #[repr(C)]
    struct _IdResourceEntry {
        unused: u16,
        id: u16,
    }

    #[repr(C)]
    #[derive(Pread)]
    struct _DataDirectoryEntry {
        offset: u32, // high-bit: 0, bits 0-31: offset
    }

    #[repr(C)]
    struct _SubDirectoryEntry {
        offset: u32, // high-bit: 1, bits 0-31: offset to another _ImageResourceDirectoryEntry
    }

    // struct _IMAGE_RESOURCE_DIRECTORY_ENTRY, winnt.h
    #[repr(C)]
    #[derive(Pread)]
    struct _ImageResourceDirectoryEntry {
        u1: _NamedResourceEntry, // union _NamedResourceEntry / _IdResourceEntry
        u2: _DataDirectoryEntry, // union _DataDirectoryEntry / _SubDirectoryEntry
    }

    // struct _IMAGE_RESOURCE_DATA_ENTRY, winnt.h
    #[repr(C)]
    #[derive(Pread)]
    struct _ImageResourceDataEntry {
        offset_to_data: u32, // offset 0
        size: u32,           // offset 4
        code_page: u32,      // offset 8
        _reserved: u32,      // offset 12
    }

    #[derive(Debug, Clone)]
    struct ImageResourceDirectoryEntry {
        id: ResourceIdType,
        code_page: u32,
        rva_to_data: usize, // relative to the start of the section / resource directory
        data_size: usize,
    }

    #[derive(Debug, PartialEq, Clone)]
    pub enum ResourceIdType {
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
        unsafe fn read_counted_str(buf: &[u8], offset: usize) -> &U16Str {
            // TODO: bounds check
            let cch = buf.pread_with::<u16>(offset, scroll::LE).unwrap() as usize;
            let str = &buf[offset + 2] as *const u8 as *const u16;
            U16Str::from_ptr(str, cch)
        }

        fn parse(
            buf: &[u8],
            directory_offset: usize,
            directory_id: ResourceIdType,
        ) -> ImageResourceEntry {
            // We don't actually care about the other fields in this structure, only the two counts
            let num_named_entries: u16 = buf.pread_with(directory_offset + 12, scroll::LE).unwrap();
            let num_id_entries: u16 = buf.pread_with(directory_offset + 14, scroll::LE).unwrap();
            let mut entries =
                Vec::with_capacity(num_named_entries as usize + num_id_entries as usize);

            let offset = directory_offset + size_of::<_ImageResourceDirectory>() as usize;

            for i in 0..num_named_entries + num_id_entries {
                let cur_offset = offset + size_of::<_ImageResourceDirectoryEntry>() * i as usize;

                let entry: _ImageResourceDirectoryEntry = buf.pread_with(cur_offset, scroll::LE).unwrap();

                let id = if entry.u1.name & 0x8000_0000 != 0 {
                    // entry is a _NamedResourceEntry

                    let name_offset = entry.u1.name & 0x7FFF_FFFF;
                    unsafe {
                        let name = Self::read_counted_str(buf, name_offset as usize);
                        ResourceIdType::Name(name.to_string().unwrap())
                    }
                } else {
                    // entry is a _IdResourceEntry
                    ResourceIdType::Id(entry.u1.name as u16)
                };

                if entry.u2.offset & 0x8000_0000 == 0 {
                    // entry is not a subdirectory
                    let offset_to_data_entry = entry.u2.offset as usize;

                    let entry_data: _ImageResourceDataEntry = buf.pread_with(offset_to_data_entry, scroll::LE).unwrap();

                    entries.push(ImageResourceEntry::Data(ImageResourceDirectoryEntry {
                        id: id,
                        code_page: entry_data.code_page,
                        rva_to_data: entry_data.offset_to_data as usize,
                        data_size: entry_data.size as usize,
                    }));
                } else {
                    // entry is another directory
                    let offset_to_subdirectory_entry = (entry.u2.offset & 0x7FFF_FFFF) as usize;
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
                                        ImageResourceEntry::Data(data) => {
                                            return Some(data.clone())
                                        }
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

    #[derive(Debug)]
    pub struct ImageResource {
        resource: ImageResourceEntry,
        resource_section_table: goblin::pe::section_table::SectionTable,
        buf: Vec<u8>,
    }

    #[derive(Debug)]
    pub struct ResourceData<'a> {
        pub id: ResourceIdType, // The resource compiler likes to put the LANGUAGE value as the ID, not the code page
        pub code_page: u32, // Usually zero?
        pub buf: &'a [u8],
    }

    impl ImageResource {
        // Win32 FindResourceW
        // Wrapper around ImageResourceEntry::find that returns only the buffer slice for the found resource
        pub fn find<T, U>(&self, name: &T, id: &U) -> Result<ResourceData, PEError>
        where
            ResourceIdType: PartialEq<T>,
            ResourceIdType: PartialEq<U>
        {
            match self.resource.find(name, id) {
                Some(dir) => {
                    // Since the RVA is relative to the loaded image layout rather than the raw image on disk,
                    // we need to adjust the RVA by the difference between those two layouts.
                    let rva_to_va_offset = (self.resource_section_table.virtual_address
                        - self.resource_section_table.pointer_to_raw_data)
                        as usize;
                    
                    let data = &self.buf[dir.rva_to_data - rva_to_va_offset
                        ..dir.rva_to_data - rva_to_va_offset + dir.data_size];

                    Ok(ResourceData { id: dir.id, code_page: dir.code_page, buf: data })
                }
                None => Err(PEError::ResourceNameNotFound()),
            }
        }
    }

    pub fn find_resource_directory_from_pe(filename: &str) -> Result<ImageResource, PEError> {
        let buf = std::fs::read(filename).map_err(|e| PEError::BadResourceString(e.to_string()))?;
        if buf.len() < 0x10 {
            panic!("file too small: {}", filename);
        }

        let _pe: Result<goblin::pe::PE, PEError> = match goblin::Object::parse(&buf)
            .map_err(|e| PEError::BadResourceString(e.to_string()))?
        {
            goblin::Object::PE(pe) => {
                if let Some(opt) = pe.header.optional_header {
                    if opt.data_directories.get_clr_runtime_header().is_some() {
                        return Err(PEError::FormatNotSupported(".NET assembly"));
                    }
                }
                Ok(pe)
            }
            goblin::Object::Elf(_) => Err(PEError::FormatNotSupported("elf")),
            goblin::Object::Archive(_) => {
                Err(PEError::FormatNotSupported("archive"))
            }
            goblin::Object::Mach(_) => Err(PEError::FormatNotSupported("macho")),
            goblin::Object::Unknown(_) => {
                Err(PEError::FormatNotSupported("unknown"))
            }
        };

        let pe = _pe?;

        let optional_header = pe.header.optional_header.unwrap();

        let resource_table = optional_header.data_directories.get_resource_table().ok_or(PEError::NoResourceTable())?;

        let resource_table_start = resource_table.virtual_address as usize;
        let resource_table_end = resource_table_start + resource_table.size as usize;

        let mut resource_section: Option<goblin::pe::section_table::SectionTable> = None;

        // Find the PE section that holds the resource table.
        // We don't really need to do this, because the resource table will almost certainly exist at the
        // very start of the section table, but it's a good sanity check anyway.

        // PE section names are mostly meaningless, so looking for the ".rsrc" section by name may not work
        for section in pe.sections {
            if section.virtual_address as usize >= resource_table_start
                && (section.virtual_address + section.virtual_size) as usize <= resource_table_end
            {
                resource_section = Some(section);
                break;
            }
        }

        let resource_section_table = resource_section.ok_or(PEError::NoResourceTable())?;

        // offset will almost always == resource_section_table.pointer_to_raw_data,
        // because the resource table will start will start exactly at the start of the section
        let offset = resource_table_start - resource_section_table.virtual_address as usize
            + resource_section_table.pointer_to_raw_data as usize;
        let end = offset + resource_section_table.virtual_size as usize;

        let section_name = resource_section_table
            .name()
            .map_err(|e| PEError::BadResourceString(e.to_string()))?;

        let resource = ImageResourceEntry::parse(
            &buf[offset..end],
            0,
            ResourceIdType::Name(section_name.to_string()),
        );

        Ok(ImageResource {
            resource,
            resource_section_table,
            buf,
        })
    }
}
