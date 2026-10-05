use std::fs;

fn main() {
    // Test if our implementation can handle the PPM-compressed file
    if let Ok(archive) = rar::Archive::extract_all("test-ppm-large.rar", "target/test-ppm/", "") {
        println!("✅ Successfully extracted PPM file!");
        println!("Archive info: {:?}", archive);
        
        // Check if extracted file matches original
        let original = fs::read_to_string("test-ppm-large.txt").unwrap();
        let extracted = fs::read_to_string("target/test-ppm/test-ppm-large.txt").unwrap();
        
        if original == extracted {
            println!("✅ Content matches perfectly!");
        } else {
            println!("❌ Content mismatch!");
        }
    } else {
        println!("❌ Failed to extract PPM file - might need PPM decoder");
    }
}
