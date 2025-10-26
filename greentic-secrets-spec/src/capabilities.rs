/// Discrete operations a backend may support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    Read,
    Write,
    List,
    Delete,
    Versions,
}

/// Capability matrix advertized by a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySet {
    pub read: bool,
    pub write: bool,
    pub list: bool,
    pub delete: bool,
    pub versions: bool,
}

impl CapabilitySet {
    pub const fn new() -> Self {
        Self {
            read: false,
            write: false,
            list: false,
            delete: false,
            versions: false,
        }
    }

    pub const fn with_read(mut self) -> Self {
        self.read = true;
        self
    }

    pub const fn with_write(mut self) -> Self {
        self.write = true;
        self
    }

    pub const fn with_list(mut self) -> Self {
        self.list = true;
        self
    }

    pub const fn with_delete(mut self) -> Self {
        self.delete = true;
        self
    }

    pub const fn with_versions(mut self) -> Self {
        self.versions = true;
        self
    }

    pub const fn supports(&self, capability: Capability) -> bool {
        match capability {
            Capability::Read => self.read,
            Capability::Write => self.write,
            Capability::List => self.list,
            Capability::Delete => self.delete,
            Capability::Versions => self.versions,
        }
    }
}
