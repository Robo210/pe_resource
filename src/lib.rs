mod rsrc {
    use core::fmt::Write;
    use thiserror::Error;
    use zerocopy::FromBytes;
    use zerocopy_derive::{FromBytes, Immutable, KnownLayout};

    #[derive(Error, Debug)]
    pub enum PEError {
        #[error("Format not supported: {0}")]
        FormatNotSupported(&'static str),

        #[error("PE file does not contain a resource table")]
        NoResourceTable(),

        #[error("Invalid resource string: {0}")]
        BadResourceString(String),

        #[error("Resource with the provided name / ID not found")]
        ResourceNameNotFound(),

        #[error("An error was returned when parsing the PE: {0}")]
        GoblinError(goblin::error::Error),

        #[error("The resource data is too small to contain the expected structure (size {0}, offset {1}, required at least {2})")]
        BufferSizeError(usize, usize, usize),
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
    #[derive(FromBytes, Immutable, KnownLayout)]
    pub struct _NamedResourceEntry {
        pub name: u32, // high-bit: 1, bits 0-31: offset
    }

    #[repr(C)]
    pub struct _IdResourceEntry {
        unused: u16,
        pub id: u16,
    }

    #[repr(C)]
    #[derive(FromBytes, Immutable, KnownLayout)]
    pub struct _DataDirectoryEntry {
        pub offset: u32, // high-bit: 0, bits 0-31: offset
    }

    #[repr(C)]
    pub struct _SubDirectoryEntry {
        pub offset: u32, // high-bit: 1, bits 0-31: offset to another _ImageResourceDirectoryEntry
    }

    // struct _IMAGE_RESOURCE_DIRECTORY_ENTRY, winnt.h
    #[repr(C)]
    #[derive(FromBytes, Immutable, KnownLayout)]
    pub struct _ImageResourceDirectoryEntry {
        pub u1: _NamedResourceEntry, // union _NamedResourceEntry / _IdResourceEntry
        pub u2: _DataDirectoryEntry, // union _DataDirectoryEntry / _SubDirectoryEntry
    }

    // struct _IMAGE_RESOURCE_DATA_ENTRY, winnt.h
    #[repr(C)]
    #[derive(FromBytes, Immutable, KnownLayout)]
    pub struct _ImageResourceDataEntry {
        pub offset_to_data: u32, // offset 0
        pub size: u32,           // offset 4
        pub code_page: u32,      // offset 8
        _reserved: u32,          // offset 12
    }

    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    pub struct ImageResourceDirectoryEntry<'a> {
        pub id: ResourceIdType<'a>,
        pub code_page: u32,
        pub rva_to_data: usize, // relative to the start of the section / resource directory
        pub data_size: usize,
    }

    #[derive(Debug, Copy, Clone)]
    pub struct IndexedString<'a> {
        buf: &'a [u16],
    }

    impl<'a> IndexedString<'a> {
        pub fn try_parse(buf: &[u8], offset: usize) -> Result<IndexedString<'_>, PEError> {
            let cch = match u16::ref_from_bytes(&buf[offset..(offset + size_of::<u16>())]) {
                Ok(cch) => *cch,
                Err(_) => {
                    return Err(PEError::BufferSizeError(
                        buf.len(),
                        offset,
                        size_of::<u16>(),
                    ));
                }
            } as usize;

            if (cch * size_of::<u16>()) + offset + size_of::<u16>() > buf.len() {
                return Err(PEError::BufferSizeError(
                    buf.len(),
                    offset,
                    (cch * size_of::<u16>()) + size_of::<u16>(),
                ));
            }

            // SAFETY: We verified that the remaining buffer is large enough to hold cch u16 characters
            unsafe {
                let u16_buf: &[u16] = core::slice::from_raw_parts(
                    (buf[offset + size_of::<u16>()..]).as_ptr() as *const u16,
                    cch,
                );
                Ok(IndexedString { buf: u16_buf })
            }
        }

        pub fn chars(&self) -> impl Iterator<Item = char> + use<'a> {
            char::decode_utf16(self.buf.iter().copied())
                .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
                .fuse()
        }
    }

    impl<'a> core::fmt::Display for IndexedString<'a> {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            for c in self.chars() {
                f.write_char(c)?;
            }

            Ok(())
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub enum ResourceIdType<'a> {
        Name(IndexedString<'a>),
        Id(u16),
    }

    // Compare "#012" as 0n12, as described in the MSDN documentation for FindResource.
    // Any string parse errors return false.
    fn compare_str_id<I: IntoIterator<Item = char>>(name: I, id: u16) -> bool {
        let mut chars = name.into_iter();
        if let Some(c) = chars.next() {
            if c == '#' {
                let mut parsed_id: u16 = 0;
                let mut has_value = false;
                for x in chars {
                    match u16::try_from(x) {
                        Err(_) => return false,
                        Ok(x) => {
                            if (48..=57).contains(&x) {
                                // '0' through '9'
                                if let Some(new_parsed_id) = parsed_id
                                    .checked_mul(10)
                                    .and_then(|v| v.checked_add(x - 48))
                                {
                                    parsed_id = new_parsed_id;
                                    has_value = true;
                                } else {
                                    return false;
                                }
                            } else if x == 0 {
                                break;
                            } else {
                                return false;
                            }
                        }
                    }
                }
                return has_value && parsed_id == id;
            }
        }
        false
    }

    fn compare_utf8_utf16_str<T>(lhs: &str, rhs: T) -> bool
    where
        T: Iterator<Item = char>,
    {
        lhs.chars().eq(rhs)
    }

    impl<'a> PartialEq<&str> for ResourceIdType<'a> {
        fn eq(&self, name: &&str) -> bool {
            match self {
                ResourceIdType::Name(x) => compare_utf8_utf16_str(name, x.chars()),
                ResourceIdType::Id(id) => compare_str_id(name.chars(), *id),
            }
        }
    }

    impl<'a> PartialEq<u16> for ResourceIdType<'a> {
        fn eq(&self, id: &u16) -> bool {
            match self {
                ResourceIdType::Id(x) => *x == *id,
                ResourceIdType::Name(name) => compare_str_id(name.chars(), *id),
            }
        }
    }

    impl<'a> core::fmt::Display for ResourceIdType<'a> {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            match self {
                ResourceIdType::Id(x) => write!(f, "{}", x),
                ResourceIdType::Name(name) => write!(f, "{}", name),
            }
        }
    }
}

pub mod parser {
    pub use crate::rsrc::PEError;
    use crate::rsrc::*;
    use core::iter::FusedIterator;
    use core::mem::size_of;
    use zerocopy::FromBytes;

    #[derive(Debug)]
    pub struct ImageResource<'a> {
        image_file: memmap2::Mmap,
        rva_to_va_offset: usize,
        resource_table_offset: usize,
        resource_table_end: usize,
        _phantom: core::marker::PhantomData<&'a u8>,
    }

    #[derive(Debug)]
    pub struct ResourceData<'a> {
        pub id: ResourceIdType<'a>, // The resource compiler likes to put the LANGUAGE value as the ID, not the code page
        pub code_page: u32,         // Usually zero?
        pub buf: &'a [u8],
    }

    #[derive(Debug)]
    pub struct Resource<'a> {
        pub name: ResourceIdType<'a>,
        pub id: ResourceIdType<'a>,
        pub data: ResourceData<'a>,
    }

    impl<'a> ImageResource<'a> {
        // Win32 FindResourceW
        // Wrapper around ImageResourceEntry::find that returns only the buffer slice for the found resource
        pub fn find<T, U>(&'a self, name: &T, id: &U) -> Result<ResourceData<'a>, PEError>
        where
            ResourceIdType<'a>: PartialEq<T>,
            ResourceIdType<'a>: PartialEq<U>,
        {
            let resources = self.try_into_iter()?;
            for resource in resources {
                let resource = resource?;
                if resource.name.eq(name) && resource.id.eq(id) {
                    return Ok(resource.data);
                }
            }

            Err(PEError::ResourceNameNotFound())
        }

        pub fn to_chars<'x>(
            &'a self,
            resource_id: ResourceIdType<'a>,
        ) -> impl Iterator<Item = char> + use<'a>
        where
            'a: 'x,
        {
            match resource_id {
                ResourceIdType::Name(name) => either::Left(name.clone().chars()),
                ResourceIdType::Id(id) => unsafe {
                    let mut val = id;
                    let ones = (val % 10) as u32;
                    val /= 10;
                    let tens = (val % 10) as u32;
                    val /= 10;
                    let hundreds = (val % 10) as u32;
                    val /= 10;
                    let thous = (val % 10) as u32;
                    val /= 10;
                    let ten_thous = (val % 10) as u32;
                    either::Right(IdIter {
                        chars: [
                            char::from_u32_unchecked('0' as u32 + ten_thous),
                            char::from_u32_unchecked('0' as u32 + thous),
                            char::from_u32_unchecked('0' as u32 + hundreds),
                            char::from_u32_unchecked('0' as u32 + tens),
                            char::from_u32_unchecked('0' as u32 + ones),
                        ],
                        index: if ten_thous != 0 {
                            0
                        } else if thous != 0 {
                            1
                        } else if hundreds != 0 {
                            2
                        } else if tens != 0 {
                            3
                        } else {
                            4
                        },
                    })
                },
            }
        }

        // Since we are lazy-parsing, this can fail if the resource is malformed
        pub fn try_into_iter(&'a self) -> Result<ImageResourceEnumerator<'a>, PEError> {
            ImageResourceEnumerator::try_parse(&self)
        }
    }

    struct IdIter {
        chars: [char; 5],
        index: usize,
    }

    impl FusedIterator for IdIter {}

    impl Iterator for IdIter {
        type Item = char;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index >= self.chars.len() {
                return None;
            }

            let ret = Some(self.chars[self.index]);
            self.index += 1;
            ret
        }
    }

    struct CurrentDirectoryState<'a> {
        id: ResourceIdType<'a>,
        directory_offset: usize,
        current_child_index: u16,
        num_children: u16,
    }

    pub struct ImageResourceEnumerator<'a> {
        image_resource: &'a ImageResource<'a>,
        current_index: usize,                    // Current index into cur_dir
        cur_dir: [CurrentDirectoryState<'a>; 3], // Arbitrary depth limit of 3 nested directories
    }

    impl<'a> ImageResourceEnumerator<'a> {
        pub fn try_parse(
            image_resource: &'a ImageResource,
        ) -> Result<ImageResourceEnumerator<'a>, PEError> {
            // Should be a compile-time assert, but Rust doesn't have those yet.
            debug_assert!(size_of::<_ImageResourceDirectory>() >= 16);

            if image_resource.resource_table_end - image_resource.resource_table_offset
                < size_of::<_ImageResourceDirectory>()
            {
                return Err(PEError::BufferSizeError(
                    image_resource.resource_table_end - image_resource.resource_table_offset,
                    0,
                    size_of::<_ImageResourceDirectory>(),
                ));
            }

            let buf: &[u8] = &image_resource.image_file
                [image_resource.resource_table_offset..image_resource.resource_table_end];

            let num_named_entries = match u16::ref_from_bytes(&buf[12..(12 + size_of::<u16>())]) {
                Ok(cch) => *cch,
                Err(_) => {
                    return Err(PEError::BufferSizeError(buf.len(), 12, size_of::<u16>()));
                }
            };

            let num_id_entries = match u16::ref_from_bytes(&buf[14..(14 + size_of::<u16>())]) {
                Ok(cch) => *cch,
                Err(_) => {
                    return Err(PEError::BufferSizeError(buf.len(), 14, size_of::<u16>()));
                }
            };

            Ok(ImageResourceEnumerator {
                image_resource,
                current_index: 0,
                cur_dir: [
                    CurrentDirectoryState {
                        id: ResourceIdType::Id(0),
                        directory_offset: 0,
                        current_child_index: 0,
                        num_children: num_named_entries + num_id_entries,
                    },
                    // These two are lazy-initialized when we descend into subdirectories
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
            })
        }
    }

    impl<'a> FusedIterator for ImageResourceEnumerator<'a> {}

    impl<'a> Iterator for ImageResourceEnumerator<'a> {
        type Item = Result<Resource<'a>, PEError>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.cur_dir[self.current_index].current_child_index
                    >= self.cur_dir[self.current_index].num_children
                {
                    // If the last item was the last in this directory, return to the parent directory
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

            let offset = directory_offset + size_of::<_ImageResourceDirectory>();

            let cur_offset = offset + size_of::<_ImageResourceDirectoryEntry>() * i as usize;

            let entry = match _ImageResourceDirectoryEntry::ref_from_prefix(&buf[cur_offset..]) {
                Ok((entry, _)) => entry,
                Err(_) => {
                    return Some(Err(PEError::BufferSizeError(
                        buf.len(),
                        cur_offset,
                        size_of::<_ImageResourceDirectoryEntry>(),
                    )));
                }
            };

            let id = if entry.u1.name & 0x8000_0000 != 0 {
                // entry is a _NamedResourceEntry

                let name_offset = entry.u1.name & 0x7FFF_FFFF;
                match IndexedString::try_parse(buf, name_offset as usize) {
                    Ok(name) => ResourceIdType::Name(name),
                    Err(_) => {
                        return None;
                    }
                }
            } else {
                // entry is a _IdResourceEntry
                ResourceIdType::Id(entry.u1.name as u16)
            };

            if entry.u2.offset & 0x8000_0000 == 0 {
                // entry is not a subdirectory
                let offset_to_data_entry = entry.u2.offset as usize;

                let entry_data =
                    match _ImageResourceDataEntry::ref_from_prefix(&buf[offset_to_data_entry..]) {
                        Ok((entry_data, _)) => entry_data,
                        Err(_) => {
                            return Some(Err(PEError::BufferSizeError(
                                buf.len(),
                                offset_to_data_entry,
                                size_of::<_ImageResourceDataEntry>(),
                            )));
                        }
                    };

                let rva_to_data = entry_data.offset_to_data as usize;
                let data_size = entry_data.size as usize;

                let data = &self.image_resource.image_file[rva_to_data
                    - self.image_resource.rva_to_va_offset
                    ..rva_to_data - self.image_resource.rva_to_va_offset + data_size];

                let mut rsrc_name = ResourceIdType::Id(0);
                let mut rsrc_id = ResourceIdType::Id(0);
                if self.current_index == 2 {
                    rsrc_name = self.cur_dir[1].id;
                    rsrc_id = self.cur_dir[2].id;
                }

                Some(Ok(Resource {
                    name: rsrc_name,
                    id: rsrc_id,
                    data: ResourceData {
                        id,
                        code_page: entry_data.code_page,
                        buf: data,
                    },
                }))
            } else {
                if self.current_index >= self.cur_dir.len() {
                    panic!("Resource directory nesting is too deep");
                }

                let offset_to_subdirectory_entry = (entry.u2.offset & 0x7FFF_FFFF) as usize;
                let num_named_entries: u16 = match u16::ref_from_bytes(
                    &buf[offset_to_subdirectory_entry + 12
                        ..(offset_to_subdirectory_entry + 12 + size_of::<u16>())],
                ) {
                    Ok(n) => *n,
                    Err(_) => {
                        return Some(Err(PEError::BufferSizeError(
                            buf.len(),
                            offset_to_subdirectory_entry + 12,
                            size_of::<u16>(),
                        )));
                    }
                };

                let num_id_entries: u16 = match u16::ref_from_bytes(
                    &buf[offset_to_subdirectory_entry + 14
                        ..(offset_to_subdirectory_entry + 14 + size_of::<u16>())],
                ) {
                    Ok(n) => *n,
                    Err(_) => {
                        return Some(Err(PEError::BufferSizeError(
                            buf.len(),
                            offset_to_subdirectory_entry + 14,
                            size_of::<u16>(),
                        )));
                    }
                };

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

    pub fn find_resource_directory_from_pe(filename: &str) -> Result<ImageResource<'_>, PEError> {
        let file =
            std::fs::File::open(filename).map_err(|e| PEError::BadResourceString(e.to_string()))?;
        let mapped = unsafe {
            memmap2::Mmap::map(&file).map_err(|e| PEError::BadResourceString(e.to_string()))?
        };
        let buf: &[u8] = &mapped;
        if buf.len() < 0x10 {
            panic!("file too small: {}", filename);
        }

        let mut pe_opts = goblin::pe::options::ParseOptions::default()
            .with_parse_mode(goblin::pe::options::ParseMode::Permissive);
        pe_opts.parse_attribute_certificates = false;
        pe_opts.parse_tls_data = false;

        let _pe: Result<goblin::pe::PE, PEError> =
            match goblin::pe::PE::parse_with_opts(buf, &pe_opts)
                .map_err(|e| PEError::BadResourceString(e.to_string()))
            {
                Ok(pe) => {
                    if let Some(opt) = pe.header.optional_header {
                        if opt.data_directories.get_clr_runtime_header().is_some() {
                            return Err(PEError::FormatNotSupported(".NET assembly"));
                        }
                    }
                    Ok(pe)
                }
                _ => Err(PEError::FormatNotSupported("unknown")),
            };

        let pe = _pe?;

        let optional_header = pe.header.optional_header.unwrap();

        let resource_table = optional_header
            .data_directories
            .get_resource_table()
            .ok_or(PEError::NoResourceTable())?;

        let resource_table_start = resource_table.virtual_address as usize;
        let resource_table_end = resource_table_start + resource_table.size as usize;

        let resource_section_table = pe
            .sections
            .iter()
            .find(|section| {
                section.virtual_address as usize >= resource_table_start
                    && (section.virtual_address + section.virtual_size) as usize
                        <= resource_table_end
            })
            .ok_or(PEError::NoResourceTable())?;

        // offset will almost always == resource_section_table.pointer_to_raw_data,
        // because the resource table will start will start exactly at the start of the section
        let offset = resource_table_start - resource_section_table.virtual_address as usize
            + resource_section_table.pointer_to_raw_data as usize;
        let end = offset + resource_section_table.virtual_size as usize;

        // Since the RVA is relative to the loaded image layout rather than the raw image on disk,
        // we need to adjust the RVA by the difference between those two layouts.
        let rva_to_va_offset = (resource_section_table.virtual_address
            - resource_section_table.pointer_to_raw_data) as usize;

        let _section_name = resource_section_table
            .name()
            .map_err(|e| PEError::BadResourceString(e.to_string()))?;

        Ok(ImageResource {
            image_file: mapped,
            rva_to_va_offset,
            resource_table_offset: offset,
            resource_table_end: end,
            _phantom: core::marker::PhantomData {},
        })
    }
}
