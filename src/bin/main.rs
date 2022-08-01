use ::rsrc::*;

fn main() -> Result<(), rsrc::PEError> {
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

    let resources = rsrc::find_resource_directory_from_pe(filename)?;

    let pmres_data2 = resources.find(&"WEVT_TEMPLATE", &"#1")?;
    // let pmres_resource_data = pmres_data2.ok_or(rsrc::PEError::NoResourceTable())?;

    println!(
        "pmres header: {:?}",
        std::str::from_utf8(&pmres_data2.buf[0..4]).unwrap_or("ERROR")
    );

    Ok(())
}
