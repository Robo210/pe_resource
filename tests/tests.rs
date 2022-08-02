#[cfg(test)]
mod functional {
    #[test]
    #[cfg(target_os = "windows")]
    fn wevtapi() -> anyhow::Result<()> {
        let resource =
            rsrc::rsrc::find_resource_directory_from_pe("C:\\windows\\system32\\wevtapi.dll")?;

        let pmres_data = resource.find(&"WEVT_TEMPLATE", &"#1")?;

        assert_eq!(std::str::from_utf8(&pmres_data.buf[0..4]).unwrap(), "CRIM");
        assert_eq!(pmres_data.id, 0x409);

        Ok(())
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn wevtsvc() -> anyhow::Result<()> {
        let resource =
            rsrc::rsrc::find_resource_directory_from_pe("C:\\windows\\system32\\wevtsvc.dll")?;

        let pmres_data = resource.find(&"WEVT_TEMPLATE", &"#1")?;

        assert_eq!(std::str::from_utf8(&pmres_data.buf[0..4]).unwrap(), "CRIM");
        assert_eq!(pmres_data.id, 0x409);

        Ok(())
    }
}
