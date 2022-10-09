#[cfg(test)]
mod functional {
    use rsrc::pe_resource::ResourceIdPartialEq;

    #[test]
    #[cfg(target_os = "windows")]
    fn wevtapi() -> anyhow::Result<()> {
        let resource = rsrc::pe_resource::find_resource_directory_from_pe(
            "C:\\windows\\system32\\wevtapi.dll",
        )?;

        let pmres_data = resource.find(&"WEVT_TEMPLATE", &"#1")?;

        assert_eq!(std::str::from_utf8(&pmres_data.buf[0..4]).unwrap(), "CRIM");
        assert!(pmres_data
            .id
            .eq_with_buffer(&resource.image_file, &0x409u16));

        Ok(())
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn wevtsvc() -> anyhow::Result<()> {
        let resource = rsrc::pe_resource::find_resource_directory_from_pe(
            "C:\\windows\\system32\\wevtsvc.dll",
        )?;

        let pmres_data = resource.find(&"WEVT_TEMPLATE", &"#1")?;

        assert_eq!(std::str::from_utf8(&pmres_data.buf[0..4]).unwrap(), "CRIM");
        assert!(pmres_data
            .id
            .eq_with_buffer(&resource.image_file, &0x409u16));

        Ok(())
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn wevtapi_enum() -> anyhow::Result<()> {
        let resources = rsrc::pe_resource::find_resource_directory_from_pe(
            "C:\\windows\\system32\\wevtapi.dll",
        )?;

        for resource in &resources {
            println!("Resource: {:?}", resource.id);
        }

        Ok(())
    }
}
