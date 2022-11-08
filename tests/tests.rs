#[cfg(test)]
mod functional {
    use ::pe_resource::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn wevtapi() -> Result<(), parser::PEError> {
        let resource =
            parser::find_resource_directory_from_pe("C:\\windows\\system32\\wevtapi.dll")?;

        let pmres_data = resource.find(&"WEVT_TEMPLATE", &"#1")?;

        assert_eq!(std::str::from_utf8(&pmres_data.buf[0..4]).unwrap(), "CRIM");
        assert!(pmres_data.id.eq(&0x409u16));

        Ok(())
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn wevtsvc() -> Result<(), parser::PEError> {
        let resource =
            parser::find_resource_directory_from_pe("C:\\windows\\system32\\wevtsvc.dll")?;

        let pmres_data = resource.find(&"WEVT_TEMPLATE", &"#1")?;

        assert_eq!(std::str::from_utf8(&pmres_data.buf[0..4]).unwrap(), "CRIM");
        assert!(pmres_data.id.eq(&0x409u16));

        Ok(())
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn wevtapi_enum() -> Result<(), parser::PEError> {
        let resources =
            parser::find_resource_directory_from_pe("C:\\windows\\system32\\wevtapi.dll")?;

        for resource in &resources {
            println!(
                "Enumerated resource: {}/{}/{}",
                resource.name,
                resource.id,
                String::from_iter(resources.to_chars(resource.data.id))
            );
        }

        Ok(())
    }
}
