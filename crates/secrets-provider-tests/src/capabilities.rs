/// Optional provider features exercised by the suite.
#[derive(Clone, Copy, Debug, Default)]
pub struct Capabilities {
    /// Supports listing secrets by prefix.
    pub list: bool,
}

impl Capabilities {
    pub const fn with_list(mut self) -> Self {
        self.list = true;
        self
    }
}
