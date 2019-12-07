# RAR Rust
This crate provides a Rust native functionality to list and extract RAR files (Right now with limited functionality!)

Please have a look in the test section of the file `src/lib.rs` to see in detail which features are supported right now and how to use this crate.

A basic example to extract the complete archive:
```rust
extern crate rar;

// Get the archive information and extract everything
let archive = rar::Archive::extract_all(
    "assets/rar5-save-32mb-txt.rar",
    "target/rar-test/rar5-save-32mb-txt/",
    "").unwrap();

// Print out the archive structure information
println!("Result: {:?}", archive);
```

# Features
**RAR 5**
- [x] Extract archive with single File
- [x] Extract archive with multiple Files
- [x] Extract split archive with multiple files
- [x] Extract encrypted archive
- [x] Extract compression SAVE
- [ ] Extract compression FASTEST
- [ ] Extract compression FAST
- [ ] Extract compression NORMAL
- [ ] Extract compression GOOD
- [ ] Extract compression BEST

**RAR 4**
- [ ] Extract archive with single File
- [ ] Extract archive with multiple Files
- [ ] Extract split archive with multiple files
- [ ] Extract encrypted archive
- [ ] Extract compression SAVE
- [ ] Extract compression FASTEST
- [ ] Extract compression FAST
- [ ] Extract compression NORMAL
- [ ] Extract compression GOOD
- [ ] Extract compression BEST

# Contributing
Please contribute! 

The goal is to make this crate feature complete :)

If you need any kind of help, open an issue or write me an mail.
Pull requests are welcome!

# License
Copyright © 2018 Robert Schütte

Distributed under the [MIT License](LICENSE).
