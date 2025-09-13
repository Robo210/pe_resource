use ::pe_resource::*;

fn main() -> Result<(), parser::PEError> {
    let filename = std::env::args()
        .nth(1)
        .expect("missing argument 1: path to input PE file");

    let resources = parser::find_resource_directory_from_pe(&filename)?;

    let pmres_data = resources.find(&"WEVT_TEMPLATE", &"#1")?;
    // let pmres_resource_data = pmres_data.ok_or(rsrc::PEError::NoResourceTable())?;

    println!(
        "pmres header: {:?}",
        std::str::from_utf8(&pmres_data.buf[0..4]).unwrap_or("ERROR")
    );

    println!("Resource tree:\n{:?}", resources);

    for resource in &resources {
        //println!("Enumerated resource: {}/{}/{}", resources.to_string(resource.name), resources.to_string(resource.id), resources.to_string(resource.data.id));
        println!(
            "Enumerated resource: {}/{}/{}",
            String::from_iter(resources.to_chars(resource.name)),
            String::from_iter(resources.to_chars(resource.id)),
            String::from_iter(resources.to_chars(resource.data.id))
        );
    }

    Ok(())
}
