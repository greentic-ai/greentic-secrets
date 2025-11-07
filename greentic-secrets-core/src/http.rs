use anyhow::{Context, Result};
use reqwest::{
    Client, Method, Response,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::time::Duration;
use url::Url;

use crate::rt;

/// Builder for [`Http`] clients that wraps `reqwest::ClientBuilder` options we
/// commonly surface to providers.
#[derive(Clone, Debug, Default)]
pub struct HttpBuilder {
    timeout: Option<Duration>,
    danger_accept_invalid_certs: bool,
    danger_accept_invalid_hostnames: bool,
    proxy: Option<Url>,
    default_headers: Option<HeaderMap>,
}

impl HttpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    pub fn danger_accept_invalid_certs(mut self, on: bool) -> Self {
        self.danger_accept_invalid_certs = on;
        self
    }

    pub fn danger_accept_invalid_hostnames(mut self, on: bool) -> Self {
        self.danger_accept_invalid_hostnames = on;
        self
    }

    /// Convenience toggle that opts into both certificate + hostname bypass.
    pub fn insecure_tls(mut self, on: bool) -> Self {
        self.danger_accept_invalid_certs = on;
        self.danger_accept_invalid_hostnames = on;
        self
    }

    pub fn proxy(mut self, url: Option<Url>) -> Self {
        self.proxy = url;
        self
    }

    pub fn default_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = Some(headers);
        self
    }

    pub fn build(self) -> Result<Http> {
        let mut builder = Client::builder().use_rustls_tls();
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        builder = builder
            .danger_accept_invalid_certs(self.danger_accept_invalid_certs)
            .danger_accept_invalid_hostnames(self.danger_accept_invalid_hostnames);
        if let Some(proxy_url) = self.proxy {
            let proxy = reqwest::Proxy::all(proxy_url.as_str())
                .with_context(|| format!("invalid proxy url: {proxy_url}"))?;
            builder = builder.proxy(proxy);
        }
        if let Some(headers) = self.default_headers {
            builder = builder.default_headers(headers);
        }
        Http::from_builder(builder)
    }
}

/// Thin synchronous facade over the async reqwest client.
#[derive(Clone)]
pub struct Http {
    client: Client,
}

impl Http {
    /// Builds a client with the provided timeout and rustls TLS stack.
    pub fn new(timeout: Duration) -> Result<Self> {
        Self::builder().timeout(timeout).build()
    }

    /// Builds a client from a custom reqwest builder.
    pub fn from_builder(builder: reqwest::ClientBuilder) -> Result<Self> {
        Ok(Self {
            client: builder.build().context("failed to build HTTP client")?,
        })
    }

    /// Starts building an HTTP client with custom provider options.
    pub fn builder() -> HttpBuilder {
        HttpBuilder::new()
    }

    /// Creates a new request with the provided method and URL.
    pub fn request(&self, method: Method, url: impl AsRef<str>) -> HttpRequest {
        let url = url.as_ref();
        let builder = self.client.request(method, url);
        HttpRequest { builder }
    }

    pub fn get(&self, url: impl AsRef<str>) -> HttpRequest {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: impl AsRef<str>) -> HttpRequest {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: impl AsRef<str>) -> HttpRequest {
        self.request(Method::PUT, url)
    }

    pub fn delete(&self, url: impl AsRef<str>) -> HttpRequest {
        self.request(Method::DELETE, url)
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

pub struct HttpRequest {
    builder: reqwest::RequestBuilder,
}

impl HttpRequest {
    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.builder = self.builder.bearer_auth(token.as_ref());
        self
    }

    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.builder = self.builder.header(name, value);
        self
    }

    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.builder = self.builder.headers(headers);
        self
    }

    pub fn json(mut self, value: &impl Serialize) -> Self {
        self.builder = self.builder.json(value);
        self
    }

    pub fn body(mut self, value: impl Into<reqwest::Body>) -> Self {
        self.builder = self.builder.body(value);
        self
    }

    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Self {
        self.builder = self.builder.query(query);
        self
    }

    pub fn form(mut self, value: &impl Serialize) -> Self {
        self.builder = self.builder.form(value);
        self
    }

    pub fn send(self) -> Result<HttpResponse> {
        rt::sync_await(async {
            let response = self.builder.send().await?;
            Ok(HttpResponse { inner: response })
        })
    }

    pub fn send_json<T: DeserializeOwned>(self) -> Result<T> {
        let response = self.send()?;
        response.json()
    }

    pub fn send_text(self) -> Result<String> {
        let response = self.send()?;
        response.text()
    }
}

pub struct HttpResponse {
    inner: Response,
}

impl HttpResponse {
    pub fn status(&self) -> reqwest::StatusCode {
        self.inner.status()
    }

    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    pub fn into_inner(self) -> Response {
        self.inner
    }

    pub fn json<T: DeserializeOwned>(self) -> Result<T> {
        rt::sync_await(async {
            self.inner
                .json::<T>()
                .await
                .context("failed to decode JSON")
        })
    }

    pub fn text(self) -> Result<String> {
        rt::sync_await(async {
            self.inner
                .text()
                .await
                .context("failed to read body as text")
        })
    }
}
