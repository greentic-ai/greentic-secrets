use crate::spec_compat::{Scope, SecretMeta, Visibility};
use crate::{errors::Result, types::validate_component};
use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// Actor attempting to perform operations on secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Principal {
    subject: String,
    scope: Scope,
    visibility: Visibility,
}

impl Principal {
    /// Construct a principal with validated attributes.
    pub fn new(subject: impl Into<String>, scope: Scope, visibility: Visibility) -> Result<Self> {
        let subject = subject.into();
        validate_component(&subject, "subject")?;
        Ok(Self {
            subject,
            scope,
            visibility,
        })
    }

    /// Subject identifier (for logging/auditing).
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Scope attached to the subject.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Maximum visibility allowed for the subject.
    pub fn visibility(&self) -> Visibility {
        self.visibility
    }
}

/// Authorization interface for secret operations.
pub trait Authorizer {
    /// Determine whether a secret can be retrieved.
    fn can_get(&self, principal: &Principal, secret: &SecretMeta) -> bool;
    /// Determine whether a secret can be created or updated.
    fn can_put(&self, principal: &Principal, secret: &SecretMeta) -> bool;
    /// Determine whether a secret may be deleted.
    fn can_delete(&self, principal: &Principal, secret: &SecretMeta) -> bool;
    /// Determine whether a secret may be rotated.
    fn can_rotate(&self, principal: &Principal, secret: &SecretMeta) -> bool;
}

/// Default policy guard implementing scope- and visibility-based access control.
#[derive(Debug, Default, Clone, Copy)]
pub struct PolicyGuard;

impl PolicyGuard {
    fn evaluate(&self, action: Action, principal: &Principal, secret: &SecretMeta) -> bool {
        if !principal.scope().matches(secret.scope()) {
            return false;
        }

        if !team_allowed(principal.scope(), secret.scope(), secret.visibility) {
            return false;
        }

        if !principal.visibility().allows(secret.visibility) {
            return false;
        }

        match action {
            Action::Get => true,
            Action::Put | Action::Delete | Action::Rotate => {
                // Restrict tenant-scoped secrets to tenant level actors for mutation.
                if secret.visibility == Visibility::Tenant {
                    principal.visibility() == Visibility::Tenant
                } else {
                    true
                }
            }
        }
    }
}

fn team_allowed(principal_scope: &Scope, secret_scope: &Scope, visibility: Visibility) -> bool {
    match visibility {
        Visibility::User | Visibility::Team => principal_scope.team_matches(secret_scope),
        Visibility::Tenant => {
            // Tenant scoped secrets ignore team boundaries.
            true
        }
    }
}

impl Authorizer for PolicyGuard {
    fn can_get(&self, principal: &Principal, secret: &SecretMeta) -> bool {
        self.evaluate(Action::Get, principal, secret)
    }

    fn can_put(&self, principal: &Principal, secret: &SecretMeta) -> bool {
        self.evaluate(Action::Put, principal, secret)
    }

    fn can_delete(&self, principal: &Principal, secret: &SecretMeta) -> bool {
        self.evaluate(Action::Delete, principal, secret)
    }

    fn can_rotate(&self, principal: &Principal, secret: &SecretMeta) -> bool {
        self.evaluate(Action::Rotate, principal, secret)
    }
}

#[derive(Clone, Copy)]
enum Action {
    Get,
    Put,
    Delete,
    Rotate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_compat::ContentType;
    use crate::uri::SecretUri;

    fn build_meta(scope: Scope, visibility: Visibility) -> SecretMeta {
        let uri = SecretUri::new(scope.clone(), "kv", "api-key").unwrap();
        SecretMeta::new(uri, visibility, ContentType::Opaque)
    }

    fn principal(
        subject: &str,
        env: &str,
        tenant: &str,
        team: Option<&str>,
        visibility: Visibility,
    ) -> Principal {
        let scope = Scope::new(
            env.to_string(),
            tenant.to_string(),
            team.map(|t| t.to_string()),
        )
        .unwrap();
        Principal::new(subject.to_string(), scope, visibility).unwrap()
    }

    #[test]
    fn acl_positive_cases() {
        let guard = PolicyGuard;

        let team_scope = Scope::new("prod", "acme", Some("payments".into())).unwrap();
        let team_meta = build_meta(team_scope.clone(), Visibility::Team);
        let team_principal = principal("alice", "prod", "acme", Some("payments"), Visibility::Team);

        assert!(guard.can_get(&team_principal, &team_meta));
        assert!(guard.can_put(&team_principal, &team_meta));
        assert!(guard.can_delete(&team_principal, &team_meta));
        assert!(guard.can_rotate(&team_principal, &team_meta));

        let tenant_scope = Scope::new("prod", "acme", None).unwrap();
        let tenant_meta = build_meta(tenant_scope.clone(), Visibility::Tenant);
        let tenant_admin = principal("tenant-admin", "prod", "acme", None, Visibility::Tenant);

        assert!(guard.can_get(&tenant_admin, &tenant_meta));
        assert!(guard.can_put(&tenant_admin, &tenant_meta));
    }

    #[test]
    fn acl_negative_cases() {
        let guard = PolicyGuard;
        let payments_scope = Scope::new("prod", "acme", Some("payments".into())).unwrap();
        let billing_scope = Scope::new("prod", "acme", Some("billing".into())).unwrap();

        let payments_meta = build_meta(payments_scope.clone(), Visibility::Team);
        let billing_principal = principal("bob", "prod", "acme", Some("billing"), Visibility::Team);

        assert!(!guard.can_get(&billing_principal, &payments_meta));
        assert!(!guard.can_put(&billing_principal, &payments_meta));

        let tenant_meta = build_meta(billing_scope.clone(), Visibility::Tenant);
        let team_operator = principal("ops", "prod", "acme", Some("billing"), Visibility::Team);

        assert!(!guard.can_put(&team_operator, &tenant_meta));
        assert!(!guard.can_delete(&team_operator, &tenant_meta));
        assert!(!guard.can_rotate(&team_operator, &tenant_meta));

        let dev_principal = principal("dave", "dev", "acme", Some("payments"), Visibility::Tenant);
        assert!(!guard.can_get(&dev_principal, &payments_meta));
    }
}
