#[derive(Debug, Fail, PartialEq)]
enum RarError {
    #[fail(display = "invalid toolchain name: {}", name)]
    InvalidToolchainName {
        name: String,
    },
    #[fail(display = "Unknown error occoured: {}", _0)]
    Unknown(String)
}