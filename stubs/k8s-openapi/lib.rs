//! Minimal subset of the `k8s-openapi` crate required by the Greentic tests.
//!
//! Only the pieces exercised by the in-repo Kubernetes backend are implemented:
//! `ObjectMeta` and `Secret`. Both types intentionally expose a small API
//! surface to keep the stub compact and predictable.
//!
//! # Testing
//! Run `cargo test -p k8s-openapi` to ensure the helper methods continue to
//! behave as expected.

/// Modules mirror the structure of the real crate for drop-in replacements.
pub mod apimachinery {
    pub mod pkg {
        pub mod apis {
            pub mod meta {
                pub mod v1 {
                    use std::collections::BTreeMap;

                    /// Minimal metadata for Kubernetes objects.
                    #[derive(Clone, Debug, Default, PartialEq, Eq)]
                    pub struct ObjectMeta {
                        pub name: Option<String>,
                        pub namespace: Option<String>,
                        pub labels: Option<BTreeMap<String, String>>,
                    }

                    impl ObjectMeta {
                        /// Convenience constructor for namespaced resources.
                        pub fn named(
                            name: impl Into<String>,
                            namespace: impl Into<String>,
                        ) -> Self {
                            Self {
                                name: Some(name.into()),
                                namespace: Some(namespace.into()),
                                ..Self::default()
                            }
                        }

                        /// Adds a label to the metadata, creating the map if needed.
                        pub fn insert_label(
                            &mut self,
                            key: impl Into<String>,
                            value: impl Into<String>,
                        ) {
                            let labels = self.labels.get_or_insert_with(BTreeMap::new);
                            labels.insert(key.into(), value.into());
                        }
                    }
                }
            }
        }
    }
}

pub mod api {
    pub mod core {
        pub mod v1 {
            use crate::apimachinery::pkg::apis::meta::v1::ObjectMeta;
            use std::collections::BTreeMap;

            /// Kubernetes Secret representation with deterministic helpers.
            #[derive(Clone, Debug, Default, PartialEq, Eq)]
            pub struct Secret {
                pub metadata: ObjectMeta,
                pub data: Option<BTreeMap<String, Vec<u8>>>,
                pub string_data: Option<BTreeMap<String, String>>,
                pub type_: Option<String>,
            }

            impl Secret {
                /// Creates a secret with the provided name and namespace.
                pub fn named(name: impl Into<String>, namespace: impl Into<String>) -> Self {
                    Self {
                        metadata: ObjectMeta::named(name, namespace),
                        data: Some(BTreeMap::new()),
                        string_data: Some(BTreeMap::new()),
                        type_: Some("Opaque".into()),
                    }
                }

                /// Inserts a key/value pair into `stringData`.
                pub fn insert_string_data(
                    &mut self,
                    key: impl Into<String>,
                    value: impl Into<String>,
                ) {
                    let entries = self.string_data.get_or_insert_with(BTreeMap::new);
                    entries.insert(key.into(), value.into());
                }

                /// Copies `stringData` into `data` using UTF-8 encoding.
                pub fn bake_string_data(&mut self) {
                    if let Some(string_data) = self.string_data.take() {
                        let data = self.data.get_or_insert_with(BTreeMap::new);
                        for (key, value) in string_data {
                            data.insert(key, value.into_bytes());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::api::core::v1::Secret;
    use super::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    #[test]
    fn metadata_helpers_populate_fields() {
        let mut meta = ObjectMeta::named("secret", "default");
        meta.insert_label("managed-by", "greentic");

        assert_eq!(meta.name.as_deref(), Some("secret"));
        assert_eq!(meta.namespace.as_deref(), Some("default"));
        assert_eq!(
            meta.labels.unwrap().get("managed-by").map(|s| s.as_str()),
            Some("greentic")
        );
    }

    #[test]
    fn baking_string_data_marshals_to_bytes() {
        let mut secret = Secret::named("api", "gtsec");
        secret.insert_string_data("payload", "{\"k\":\"v\"}");
        secret.insert_string_data("token", "abcd");
        secret.bake_string_data();

        let payload = secret
            .data
            .as_ref()
            .unwrap()
            .get("payload")
            .expect("payload present");
        assert_eq!(payload, b"{\"k\":\"v\"}");

        // Ensure string_data is cleared after baking.
        assert!(secret.string_data.is_none());
    }
}
