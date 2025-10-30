/// Context describing the tenant that issued a secrets request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantCtx {
    env: String,
    tenant: String,
    team: Option<String>,
    user: Option<String>,
}

impl TenantCtx {
    pub fn new<E, T>(env: E, tenant: T) -> Self
    where
        E: Into<String>,
        T: Into<String>,
    {
        Self {
            env: env.into(),
            tenant: tenant.into(),
            team: None,
            user: None,
        }
    }

    pub fn with_team<S: Into<String>>(mut self, team: Option<S>) -> Self {
        self.team = team.map(Into::into);
        self
    }

    pub fn with_user<S: Into<String>>(mut self, user: Option<S>) -> Self {
        self.user = user.map(Into::into);
        self
    }

    pub fn environment(&self) -> &str {
        &self.env
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn team(&self) -> Option<&str> {
        self.team.as_deref()
    }

    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    pub fn kind(&self) -> ScopeKind {
        match (self.team.as_deref(), self.user.as_deref()) {
            (Some(team), Some(user)) => ScopeKind::User {
                env: &self.env,
                tenant: &self.tenant,
                team,
                user,
            },
            (Some(team), None) => ScopeKind::Team {
                env: &self.env,
                tenant: &self.tenant,
                team,
            },
            (None, _) => ScopeKind::Tenant {
                env: &self.env,
                tenant: &self.tenant,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ScopeKind<'a> {
    Global {
        env: &'a str,
    },
    Tenant {
        env: &'a str,
        tenant: &'a str,
    },
    Team {
        env: &'a str,
        tenant: &'a str,
        team: &'a str,
    },
    User {
        env: &'a str,
        tenant: &'a str,
        team: &'a str,
        user: &'a str,
    },
}
