mod rsrc {
    #[cfg(feature = "alloc")]
    use core::mem::size_of;
    use scroll::Pread;
    use thiserror::Error;
    use widestring::{U16Str, U16String};

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
        GoblinError(goblin::error::Error),
    }

    // struct _IMAGE_RESOURCE_DIRECTORY, winnt.h
    #[repr(C)]
    pub struct _ImageResourceDirectory {
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
    pub struct _NamedResourceEntry {
        pub name: u32, // high-bit: 1, bits 0-31: offset
    }

    #[repr(C)]
    pub struct _IdResourceEntry {
        unused: u16,
        pub id: u16,
    }

    #[repr(C)]
    #[derive(Pread)]
    pub struct _DataDirectoryEntry {
        pub offset: u32, // high-bit: 0, bits 0-31: offset
    }

    #[repr(C)]
    pub struct _SubDirectoryEntry {
        pub offset: u32, // high-bit: 1, bits 0-31: offset to another _ImageResourceDirectoryEntry
    }

    // struct _IMAGE_RESOURCE_DIRECTORY_ENTRY, winnt.h
    #[repr(C)]
    #[derive(Pread)]
    pub struct _ImageResourceDirectoryEntry {
        pub u1: _NamedResourceEntry, // union _NamedResourceEntry / _IdResourceEntry
        pub u2: _DataDirectoryEntry, // union _DataDirectoryEntry / _SubDirectoryEntry
    }

    // struct _IMAGE_RESOURCE_DATA_ENTRY, winnt.h
    #[repr(C)]
    #[derive(Pread)]
    pub struct _ImageResourceDataEntry {
        pub offset_to_data: u32, // offset 0
        pub size: u32,           // offset 4
        pub code_page: u32,      // offset 8
        _reserved: u32,          // offset 12
    }

    #[derive(Debug, Clone)]
    pub struct ImageResourceDirectoryEntry {
        pub id: ResourceIdType,
        pub code_page: u32,
        pub rva_to_data: usize, // relative to the start of the section / resource directory
        pub data_size: usize,
    }

    #[derive(Debug, Copy, Clone)]
    pub struct IndexedString {
        pub offset: usize,
        pub cch: usize,
    }

    impl IndexedString {
        pub fn new(buf: &[u8], offset: usize) -> IndexedString {
            let cch = buf.pread_with::<u16>(offset, scroll::LE).unwrap() as usize;
            if (cch * 2) + offset + 2 > buf.len() {
                panic!("oh noes");
            }
            IndexedString {
                offset: offset + 2,
                cch,
            }
        }

        pub fn fmt_with_buffer(&self, buf: &[u8], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.to_string_with_buffer(buf))
        }

        pub fn to_string_with_buffer(&self, buf: &[u8]) -> String {
            unsafe {
                let p = &buf[self.offset] as *const u8 as *const u16;
                let name_str: &U16Str = U16Str::from_ptr(p, self.cch);
                name_str.to_string().unwrap()
            }
        }
    }

    // impl std::fmt::Display for IndexedString {
    //     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    //         let
    //     }
    // }

    pub trait ResourceIdPartialEq<Rhs: ?Sized = Self> {
        fn eq_with_buffer(&self, buf: &[u8], other: &Rhs) -> bool;
    }

    #[derive(Debug, Copy, Clone)]
    pub enum ResourceIdType {
        Name(IndexedString),
        Id(u16),
    }

    // Compare "#012" as 0n12, as described in the MSDN documentation for FindResource.
    // Any string parse errors return false.
    fn compare_str_id(name: &U16Str, id: u16) -> bool {
        if !name.is_empty() {
            let mut chars_lossy = name.as_slice().iter();
            if let Some(c) = chars_lossy.next() {
                if *c == 35 {
                    // 35 == '#'
                    let mut parsed_id: u16 = 0;
                    let mut has_value = false;
                    for x in chars_lossy {
                        if *x >= 48 && *x <= 57 {
                            // '0' through '9'
                            parsed_id = parsed_id * 10 + (*x - 48); // TODO: Check for u16 overflow
                            has_value = true;
                        } else if *x == 0 {
                            break;
                        } else {
                            return false;
                        }
                    }
                    return has_value && parsed_id == id;
                }
            }
        }
        false
    }

    impl ResourceIdPartialEq<&str> for ResourceIdType {
        fn eq_with_buffer(&self, buf: &[u8], name: &&str) -> bool {
            let utf16_name = U16String::from_str(name);
            match self {
                ResourceIdType::Name(x) => unsafe {
                    let p = &buf[x.offset] as *const u8 as *const u16;
                    let name_str: &U16Str = U16Str::from_ptr(p, x.cch);
                    name_str == utf16_name.as_ustr()
                },
                ResourceIdType::Id(id) => compare_str_id(&utf16_name, *id),
            }
        }
    }

    impl ResourceIdPartialEq<u16> for ResourceIdType {
        fn eq_with_buffer(&self, buf: &[u8], id: &u16) -> bool {
            match self {
                ResourceIdType::Id(x) => *x == *id,
                ResourceIdType::Name(name) => unsafe {
                    let p = &buf[name.offset] as *const u8 as *const u16;
                    let name_str: &U16Str = U16Str::from_ptr(p, name.cch);
                    compare_str_id(name_str, *id)
                },
            }
        }
    }

    impl ResourceIdType {
        pub fn to_string_with_buffer(&self, buf: &[u8]) -> String {
            match self {
                ResourceIdType::Id(x) => x.to_string(),
                ResourceIdType::Name(name) => name.to_string_with_buffer(buf)
            }
        }
    }

    #[allow(unused)]
    #[derive(Debug)]
    pub struct ImageResourceDirectoryRoot {
        id: ResourceIdType,
        sub_directories: Vec<ImageResourceEntry>,
    }

    #[allow(unused)]
    #[derive(Debug)]
    pub enum ImageResourceEntry {
        Directory(ImageResourceDirectoryRoot),
        Data(ImageResourceDirectoryEntry),
    }

    impl ImageResourceEntry {
        #[cfg(feature = "alloc")]
        pub fn parse(
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

                let entry: _ImageResourceDirectoryEntry =
                    buf.pread_with(cur_offset, scroll::LE).unwrap();

                let id = if entry.u1.name & 0x8000_0000 != 0 {
                    // entry is a _NamedResourceEntry

                    let name_offset = entry.u1.name & 0x7FFF_FFFF;
                    let name = IndexedString::new(buf, name_offset as usize);
                    ResourceIdType::Name(name)
                } else {
                    // entry is a _IdResourceEntry
                    ResourceIdType::Id(entry.u1.name as u16)
                };

                if entry.u2.offset & 0x8000_0000 == 0 {
                    // entry is not a subdirectory
                    let offset_to_data_entry = entry.u2.offset as usize;

                    let entry_data: _ImageResourceDataEntry =
                        buf.pread_with(offset_to_data_entry, scroll::LE).unwrap();

                    entries.push(ImageResourceEntry::Data(ImageResourceDirectoryEntry {
                        id: id,
                        code_page: entry_data.code_page,
                        rva_to_data: entry_data.offset_to_data as usize,
                        data_size: entry_data.size as usize,
                    }));
                } else {
                    // entry is another directory
                    let offset_to_subdirectory_entry = (entry.u2.offset & 0x7FFF_FFFF) as usize;
                    let subdirectory = Self::parse(buf, offset_to_subdirectory_entry, id);

                    entries.push(subdirectory);
                }
            }

            ImageResourceEntry::Directory(ImageResourceDirectoryRoot {
                id: directory_id,
                sub_directories: entries,
            })
        }

        #[allow(unused)]
        #[cfg(not(feature = "alloc"))]
        pub fn parse(
            buf: &[u8],
            directory_offset: usize,
            directory_id: ResourceIdType,
        ) -> core::marker::PhantomData<u8> {
            core::marker::PhantomData
        }

        // Win32 FindResourceW
        #[cfg(feature = "alloc")]
        pub fn find<T, U>(
            &self,
            name: &T,
            id: &U,
            buf: &[u8],
        ) -> Option<ImageResourceDirectoryEntry>
        where
            ResourceIdType: ResourceIdPartialEq<T>,
            ResourceIdType: ResourceIdPartialEq<U>,
        {
            match self {
                ImageResourceEntry::Directory(root) => {
                    for item in root.sub_directories.iter() {
                        if let ImageResourceEntry::Directory(dir) = item {
                            if dir.id.eq_with_buffer(buf, name) {
                                let x = dir.sub_directories.iter().find(|subdir| {
                                    if let ImageResourceEntry::Directory(child) = subdir {
                                        if child.id.eq_with_buffer(buf, id) {
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
}

pub mod pe_resource {
    pub use crate::rsrc::PEError;
    pub use crate::rsrc::ResourceIdPartialEq;
    use crate::rsrc::*;
    use core::mem::size_of;
    use scroll::Pread;
    use std::iter::FusedIterator;

    #[derive(Debug)]
    pub struct ImageResource<'a> {
        #[cfg(feature = "alloc")]
        resource: ImageResourceEntry,
        #[cfg(not(feature = "alloc"))]
        resource: core::marker::PhantomData<u8>,
        resource_section_table: goblin::pe::section_table::SectionTable,
        pub image_file: memmap2::Mmap,
        resource_table_offset: usize,
        resource_table_end: usize,
        _phantom: std::marker::PhantomData<&'a u8>,
    }

    #[derive(Debug)]
    pub struct ResourceData<'a> {
        pub id: ResourceIdType, // The resource compiler likes to put the LANGUAGE value as the ID, not the code page
        pub code_page: u32,     // Usually zero?
        pub buf: &'a [u8],
    }

    #[derive(Debug)]
    pub struct Resource<'a> {
        pub name: ResourceIdType,
        pub id: ResourceIdType,
        pub data: ResourceData<'a>,
    }

    impl<'a> ImageResource<'a> {
        // Win32 FindResourceW
        // Wrapper around ImageResourceEntry::find that returns only the buffer slice for the found resource
        #[cfg(feature = "alloc")]
        pub fn find<T, U>(&self, name: &T, id: &U) -> Result<ResourceData, PEError>
        where
            ResourceIdType: ResourceIdPartialEq<T>,
            ResourceIdType: ResourceIdPartialEq<U>,
        {
            match self.resource.find(
                name,
                id,
                &self.image_file[self.resource_table_offset..self.resource_table_end],
            ) {
                Some(dir) => {
                    // Since the RVA is relative to the loaded image layout rather than the raw image on disk,
                    // we need to adjust the RVA by the difference between those two layouts.
                    let rva_to_va_offset = (self.resource_section_table.virtual_address
                        - self.resource_section_table.pointer_to_raw_data)
                        as usize;

                    let data = &self.image_file[dir.rva_to_data - rva_to_va_offset
                        ..dir.rva_to_data - rva_to_va_offset + dir.data_size];

                    Ok(ResourceData {
                        id: dir.id,
                        code_page: dir.code_page,
                        buf: data,
                    })
                }
                None => Err(PEError::ResourceNameNotFound()),
            }
        }

        // Win32 FindResourceW
        // Wrapper around ImageResourceEntry::find that returns only the buffer slice for the found resource
        #[cfg(not(feature = "alloc"))]
        pub fn find<T, U>(&self, name: &T, id: &U) -> Result<ResourceData, PEError>
        where
            ResourceIdType: ResourceIdPartialEq<T>,
            ResourceIdType: ResourceIdPartialEq<U>,
        {
            let buf = &self.image_file[self.resource_table_offset..self.resource_table_end];

            for resource in self.iter() {
                if resource.name.eq_with_buffer(buf, name) && resource.id.eq_with_buffer(buf, id) {
                    return Ok(resource.data);
                }
            }

            Err(PEError::ResourceNameNotFound())
        }

        pub fn iter(&'a self) -> ImageResourceEnumerator<'a> {
            self.into_iter()
        }

        pub fn to_string(&self, resource_id: ResourceIdType) -> String {
            let buf = &self.image_file[self.resource_table_offset..self.resource_table_end];
            resource_id.to_string_with_buffer(buf)
        }
    }

    impl<'a> IntoIterator for &'a ImageResource<'a> {
        type Item = <ImageResourceEnumerator<'a> as Iterator>::Item;
        type IntoIter = ImageResourceEnumerator<'a>;

        fn into_iter(self) -> Self::IntoIter {
            ImageResourceEnumerator::new(self)
        }
    }

    struct CurrentDirectoryState {
        id: ResourceIdType,
        directory_offset: usize,
        current_child_index: u16,
        num_children: u16,
    }

    pub struct ImageResourceEnumerator<'a> {
        image_resource: &'a ImageResource<'a>,
        current_index: usize,                // Current index into cur_dir
        cur_dir: [CurrentDirectoryState; 3], // Arbitrary depth limit of 3 nested directories
    }

    impl<'a> ImageResourceEnumerator<'a> {
        pub fn new(image_resource: &'a ImageResource) -> ImageResourceEnumerator<'a> {
            let buf: &[u8] = &image_resource.image_file
                [image_resource.resource_table_offset..image_resource.resource_table_end];
            let num_named_entries: u16 = buf.pread_with(12, scroll::LE).unwrap();
            let num_id_entries: u16 = buf.pread_with(14, scroll::LE).unwrap();

            ImageResourceEnumerator {
                image_resource,
                current_index: 0,
                cur_dir: [
                    CurrentDirectoryState {
                        id: ResourceIdType::Id(0),
                        directory_offset: 0,
                        current_child_index: 0,
                        num_children: num_named_entries + num_id_entries,
                    },
                    CurrentDirectoryState {
                        id: ResourceIdType::Id(0),
                        directory_offset: 0,
                        current_child_index: 0,
                        num_children: 0,
                    },
                    CurrentDirectoryState {
                        id: ResourceIdType::Id(0),
                        directory_offset: 0,
                        current_child_index: 0,
                        num_children: 0,
                    },
                ],
            }
        }
    }

    impl<'a> FusedIterator for ImageResourceEnumerator<'a> {}

    impl<'a> Iterator for ImageResourceEnumerator<'a> {
        type Item = Resource<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.cur_dir[self.current_index].current_child_index
                    >= self.cur_dir[self.current_index].num_children
                {
                    // If the last item was the last in this directory, so return to the parent directory
                    if self.current_index > 0 {
                        self.current_index -= 1;
                    } else {
                        return None;
                    }
                } else {
                    break;
                }
            }

            let buf: &[u8] = &self.image_resource.image_file
                [self.image_resource.resource_table_offset..self.image_resource.resource_table_end];
            let directory_offset = self.cur_dir[self.current_index].directory_offset;
            let i = self.cur_dir[self.current_index].current_child_index;

            self.cur_dir[self.current_index].current_child_index += 1;

            let offset = directory_offset + size_of::<_ImageResourceDirectory>() as usize;

            let cur_offset = offset + size_of::<_ImageResourceDirectoryEntry>() * i as usize;

            let entry: _ImageResourceDirectoryEntry =
                buf.pread_with(cur_offset, scroll::LE).unwrap();

            let id = if entry.u1.name & 0x8000_0000 != 0 {
                // entry is a _NamedResourceEntry

                let name_offset = entry.u1.name & 0x7FFF_FFFF;
                let name = IndexedString::new(buf, name_offset as usize);
                ResourceIdType::Name(name)
            } else {
                // entry is a _IdResourceEntry
                ResourceIdType::Id(entry.u1.name as u16)
            };

            if entry.u2.offset & 0x8000_0000 == 0 {
                // entry is not a subdirectory
                let offset_to_data_entry = entry.u2.offset as usize;

                let entry_data: _ImageResourceDataEntry =
                    buf.pread_with(offset_to_data_entry, scroll::LE).unwrap();

                // Since the RVA is relative to the loaded image layout rather than the raw image on disk,
                // we need to adjust the RVA by the difference between those two layouts.
                let rva_to_va_offset = (self.image_resource.resource_section_table.virtual_address
                    - self
                        .image_resource
                        .resource_section_table
                        .pointer_to_raw_data) as usize;

                let rva_to_data = entry_data.offset_to_data as usize;
                let data_size = entry_data.size as usize;

                let data = &self.image_resource.image_file
                    [rva_to_data - rva_to_va_offset..rva_to_data - rva_to_va_offset + data_size];

                let mut rsrc_name = ResourceIdType::Id(0);
                let mut rsrc_id = ResourceIdType::Id(0);
                if self.current_index == 2 {
                    rsrc_name = self.cur_dir[1].id;
                    rsrc_id = self.cur_dir[2].id;
                }

                Some(Resource {
                    name: rsrc_name,
                    id: rsrc_id,
                    data: ResourceData {
                        id,
                        code_page: entry_data.code_page,
                        buf: data,
                    },
                })
            } else {
                if self.current_index >= self.cur_dir.len() {
                    panic!("Resource directory nesting is too deep");
                }

                let offset_to_subdirectory_entry = (entry.u2.offset & 0x7FFF_FFFF) as usize;
                let num_named_entries: u16 = buf
                    .pread_with(offset_to_subdirectory_entry + 12, scroll::LE)
                    .unwrap();
                let num_id_entries: u16 = buf
                    .pread_with(offset_to_subdirectory_entry + 14, scroll::LE)
                    .unwrap();

                self.current_index += 1;
                self.cur_dir[self.current_index] = CurrentDirectoryState {
                    id,
                    directory_offset: offset_to_subdirectory_entry,
                    current_child_index: 0,
                    num_children: num_named_entries + num_id_entries,
                };

                self.next()
            }
        }
    }

    pub fn find_resource_directory_from_pe(filename: &str) -> Result<ImageResource, PEError> {
        let file =
            std::fs::File::open(filename).map_err(|e| PEError::BadResourceString(e.to_string()))?;
        let mapped = unsafe {
            memmap2::Mmap::map(&file).map_err(|e| PEError::BadResourceString(e.to_string()))?
        };
        let buf: &[u8] = &mapped;
        if buf.len() < 0x10 {
            panic!("file too small: {}", filename);
        }

        let _pe: Result<goblin::pe::PE, PEError> = match goblin::Object::parse(buf)
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
            goblin::Object::Archive(_) => Err(PEError::FormatNotSupported("archive")),
            goblin::Object::Mach(_) => Err(PEError::FormatNotSupported("macho")),
            goblin::Object::Unknown(_) => Err(PEError::FormatNotSupported("unknown")),
        };

        let pe = _pe?;

        let optional_header = pe.header.optional_header.unwrap();

        let resource_table = optional_header
            .data_directories
            .get_resource_table()
            .ok_or(PEError::NoResourceTable())?;

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

        let _section_name = resource_section_table
            .name()
            .map_err(|e| PEError::BadResourceString(e.to_string()))?;

        let resource = ImageResourceEntry::parse(
            &buf[offset..end],
            0,
            ResourceIdType::Id(0), // ResourceIdType::Name(section_name.to_string()),
        );

        Ok(ImageResource {
            resource,
            resource_section_table,
            image_file: mapped,
            resource_table_offset: offset,
            resource_table_end: end,
            _phantom: core::marker::PhantomData {},
        })
    }
}
