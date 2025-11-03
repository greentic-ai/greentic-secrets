#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

pub mod value {
    use super::String;
    #[cfg(not(feature = "std"))]
    use core::cmp;
    #[cfg(feature = "std")]
    use std::cmp;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SecretValue(pub String);

    impl SecretValue {
        pub fn into_string(self) -> String {
            self.0
        }

        pub fn redact_preview(&self) -> String {
            let n = self.0.len();
            match n {
                0..=4 => "****".into(),
                _ => {
                    let prefix = cmp::min(4, n);
                    format!("{prefix_head}****", prefix_head = &self.0[..prefix])
                }
            }
        }
    }
}

pub mod error {
    use super::String;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum SecretsError {
        #[error("secret not found: {0}")]
        NotFound(String),
        #[error("backend error: {0}")]
        Backend(String),
        #[error("invalid secret value for {0}: {1}")]
        Invalid(String, String),
    }

    pub type Result<T> = core::result::Result<T, SecretsError>;
}

pub mod spec {
    use super::{
        String, Vec,
        error::{Result, SecretsError},
    };

    pub struct SecretSpec {
        pub name: String,
        pub description: Option<String>,
        pub required: bool,
        validator: Option<fn(&str) -> bool>,
    }

    impl SecretSpec {
        pub fn new<N: Into<String>>(name: N) -> Self {
            Self {
                name: name.into(),
                description: None,
                required: false,
                validator: None,
            }
        }

        pub fn description<D: Into<String>>(mut self, description: D) -> Self {
            self.description = Some(description.into());
            self
        }

        pub fn required(mut self) -> Self {
            self.required = true;
            self
        }

        pub fn validator(mut self, f: fn(&str) -> bool) -> Self {
            self.validator = Some(f);
            self
        }

        pub fn validate(&self, value: &str) -> Result<()> {
            if let Some(f) = self.validator {
                if !f(value) {
                    return Err(SecretsError::Invalid(
                        self.name.clone(),
                        "validator failed".into(),
                    ));
                }
            }
            Ok(())
        }
    }

    #[derive(Default)]
    pub struct SecretSpecRegistry {
        specs: Vec<SecretSpec>,
    }

    impl SecretSpecRegistry {
        pub fn register(&mut self, spec: SecretSpec) {
            self.specs.push(spec);
        }

        pub fn validate_value(&self, name: &str, value: &str) -> Result<()> {
            if let Some(spec) = self.specs.iter().find(|s| s.name == name) {
                spec.validate(value)
            } else {
                Ok(())
            }
        }

        pub fn to_markdown(&self) -> String {
            let mut md = String::from("| Name | Description | Required |\n|---|---|---|\n");
            for spec in &self.specs {
                md.push_str(&format!(
                    "| {} | {} | {} |\n",
                    spec.name,
                    spec.description.clone().unwrap_or_default(),
                    if spec.required { "yes" } else { "no" }
                ));
            }
            md
        }
    }
}

pub mod backend {
    use super::{error::Result, value::SecretValue};

    /// Minimal backend trait providers implement.
    pub trait SecretsBackend: Send + Sync + 'static {
        /// keys like "env:DB_URL", "aws:ssm:/path", etc.
        fn get(&self, key: &str) -> Result<SecretValue>;
    }
}

pub use backend::SecretsBackend;
pub use error::{Result, SecretsError};
pub use spec::{SecretSpec, SecretSpecRegistry};
pub use value::SecretValue;
