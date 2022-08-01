#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "windows")]
    fn wevtapi() -> anyhow::Result<()> {
        let resource =
            rsrc::rsrc::find_resource_directory_from_pe("C:\\windows\\system32\\wevtapi.dll")?;

        let pmres_data = resource.find(&"WEVT_TEMPLATE", &"#1")?;

        assert_eq!(std::str::from_utf8(&pmres_data.buf[0..4]).unwrap(), "CRIM");

        Ok(())
    }
}
