use crate::{GreenticConfig, ProvenanceMap};
use greentic_config_types::ProvenancePath;
use serde::Serialize;
use std::fmt;

#[derive(Clone, Debug, Serialize)]
pub struct ExplainReport {
    pub config: GreenticConfig,
    pub provenance: ProvenanceMap,
    pub warnings: Vec<String>,
}

impl ExplainReport {
    pub fn new(config: GreenticConfig, provenance: ProvenanceMap, warnings: Vec<String>) -> Self {
        Self {
            config,
            provenance,
            warnings,
        }
    }

    pub fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "config": &self.config,
            "provenance": self.provenance_as_vec(),
            "warnings": &self.warnings,
        })
    }

    fn provenance_as_vec(&self) -> Vec<(&ProvenancePath, &crate::ConfigSource)> {
        self.provenance.iter().collect()
    }
}

impl fmt::Display for ExplainReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Greentic configuration")?;
        for (path, source) in &self.provenance {
            writeln!(f, " - {path}: {source:?}")?;
        }
        if !self.warnings.is_empty() {
            writeln!(f, "Warnings:")?;
            for warn in &self.warnings {
                writeln!(f, " ! {warn}")?;
            }
        }
        Ok(())
    }
}
