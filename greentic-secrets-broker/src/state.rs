use std::sync::Arc;

use crate::auth::Authorizer;
use secrets_core::backend::SecretsBackend;
use secrets_core::key_provider::KeyProvider;
use secrets_core::SecretsBroker;
use tokio::sync::Mutex;

pub type SharedBroker = Arc<Mutex<SecretsBroker<Box<dyn SecretsBackend>, Box<dyn KeyProvider>>>>;
pub type SharedAuthorizer = Arc<Authorizer>;

#[derive(Clone)]
pub struct AppState {
    pub broker: SharedBroker,
    pub authorizer: SharedAuthorizer,
}

impl AppState {
    pub fn new(broker: SharedBroker, authorizer: SharedAuthorizer) -> Self {
        Self { broker, authorizer }
    }
}
