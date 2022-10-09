use ::rsrc::*;

fn main() -> Result<(), pe_resource::PEError> {
    let filename = std::env::args()
        .nth(1)
        .expect("missing argument 1: path to input PE file");

    let resources = pe_resource::find_resource_directory_from_pe(&filename)?;

    let pmres_data2 = resources.find(&"WEVT_TEMPLATE", &"#1")?;
    // let pmres_resource_data = pmres_data2.ok_or(rsrc::PEError::NoResourceTable())?;

    println!(
        "pmres header: {:?}",
        std::str::from_utf8(&pmres_data2.buf[0..4]).unwrap_or("ERROR")
    );

    println!("Resource tree:\n{:?}", resources);

    for resource in resources.iter() {
        println!("Enumerated resource: {}/{}/{}", resources.to_string(resource.name), resources.to_string(resource.id), resources.to_string(resource.data.id));
    }

    Ok(())
}
