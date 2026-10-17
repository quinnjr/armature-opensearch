//! OpenSearch client configuration.

use std::time::Duration;

/// OpenSearch client configuration.
///
/// The `Debug` impl redacts `password` and any `user:pass@` userinfo
/// embedded in `urls`, so the config can be logged without leaking
/// credentials.
#[derive(Clone)]
#[non_exhaustive]
pub struct OpenSearchConfig {
    /// OpenSearch URL(s).
    pub urls: Vec<String>,
    /// Basic auth username.
    pub username: Option<String>,
    /// Basic auth password.
    pub password: Option<String>,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Request timeout.
    pub request_timeout: Duration,
    /// TLS configuration.
    pub tls: Option<TlsConfig>,
    /// AWS region (for AWS OpenSearch Service).
    #[cfg(feature = "aws-auth")]
    pub aws_region: Option<String>,
    /// Credentials provider used to sign requests with AWS SigV4 when
    /// [`OpenSearchConfig::aws_region`] is set. Required for AWS OpenSearch
    /// Service / OpenSearch Serverless authentication; without it, requests
    /// are sent unsigned even if `aws_region` is configured.
    #[cfg(feature = "aws-auth")]
    pub aws_credentials_provider: Option<aws_credential_types::provider::SharedCredentialsProvider>,
    /// Enable request compression.
    pub compression: bool,
}

impl std::fmt::Debug for OpenSearchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("OpenSearchConfig");
        d.field("urls", &redact_urls_for_logging(&self.urls))
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("tls", &self.tls);
        #[cfg(feature = "aws-auth")]
        d.field("aws_region", &self.aws_region).field(
            "aws_credentials_provider",
            &self.aws_credentials_provider.as_ref().map(|_| "<redacted>"),
        );
        d.field("compression", &self.compression).finish()
    }
}

/// Strip userinfo (`user:pass@`) from a node URL so it can be logged
/// safely. The *last* `@` inside the authority is used, so an unencoded `@`
/// in the password does not leave part of the credentials behind.
pub(crate) fn redact_url_for_logging(url: &str) -> String {
    let after_scheme = url.find("://").map(|i| i + 3).unwrap_or(0);
    let authority_end = url[after_scheme..]
        .find(['/', '?', '#'])
        .map(|i| after_scheme + i)
        .unwrap_or(url.len());
    match url[after_scheme..authority_end].rfind('@') {
        Some(at) => format!(
            "{}***@{}",
            &url[..after_scheme],
            &url[after_scheme + at + 1..]
        ),
        None => url.to_string(),
    }
}

/// [`redact_url_for_logging`] applied to every URL in a list.
pub(crate) fn redact_urls_for_logging(urls: &[String]) -> Vec<String> {
    urls.iter().map(|u| redact_url_for_logging(u)).collect()
}

impl OpenSearchConfig {
    /// Create a new configuration with a single URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
            username: None,
            password: None,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            tls: None,
            #[cfg(feature = "aws-auth")]
            aws_region: None,
            #[cfg(feature = "aws-auth")]
            aws_credentials_provider: None,
            compression: true,
        }
    }

    /// Create configuration with multiple URLs for a cluster.
    pub fn cluster(urls: Vec<String>) -> Self {
        Self {
            urls,
            ..Self::new("")
        }
    }

    /// Set basic authentication credentials.
    pub fn with_basic_auth(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Set connection timeout.
    ///
    /// Note: not applied by the current transport (opensearch 2.4 TransportBuilder cannot
    /// express it); see `OpenSearchClient::new`.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set TLS configuration.
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Set AWS region for AWS OpenSearch Service.
    ///
    /// This alone does not enable request signing: pair it with
    /// [`OpenSearchConfig::with_aws_credentials_provider`] so `OpenSearchClient::new`
    /// has credentials to sign with. If a region is set without a credentials
    /// provider, `OpenSearchClient::new` returns a validation error rather than
    /// silently sending unsigned requests.
    #[cfg(feature = "aws-auth")]
    pub fn with_aws_region(mut self, region: impl Into<String>) -> Self {
        self.aws_region = Some(region.into());
        self
    }

    /// Set the credentials provider used to sign requests with AWS SigV4.
    ///
    /// Callers typically obtain a provider from `aws-config`'s default chain,
    /// e.g. `aws_config::load_defaults(BehaviorVersion::latest()).await.credentials_provider()`,
    /// or supply a fixed/test provider via
    /// `aws_credential_types::provider::SharedCredentialsProvider::new(...)`.
    #[cfg(feature = "aws-auth")]
    pub fn with_aws_credentials_provider(
        mut self,
        provider: aws_credential_types::provider::SharedCredentialsProvider,
    ) -> Self {
        self.aws_credentials_provider = Some(provider);
        self
    }

    /// Enable or disable compression.
    ///
    /// Note: not applied by the current transport (opensearch 2.4 TransportBuilder cannot
    /// express it); see `OpenSearchClient::new`.
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression = enabled;
        self
    }
}

/// TLS configuration.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// Path to CA certificate.
    pub ca_cert: Option<String>,
    /// Path to client certificate.
    pub client_cert: Option<String>,
    /// Path to client key.
    pub client_key: Option<String>,
    /// Skip certificate verification (not recommended for production).
    pub danger_accept_invalid_certs: bool,
}

impl TlsConfig {
    /// Create TLS config with CA certificate.
    pub fn with_ca_cert(ca_cert: impl Into<String>) -> Self {
        Self {
            ca_cert: Some(ca_cert.into()),
            ..Default::default()
        }
    }

    /// Set client certificate and key for mutual TLS.
    pub fn with_client_cert(mut self, cert: impl Into<String>, key: impl Into<String>) -> Self {
        self.client_cert = Some(cert.into());
        self.client_key = Some(key.into());
        self
    }

    /// Skip certificate verification (DANGER: only for development).
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.danger_accept_invalid_certs = true;
        self
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn debug_redacts_password_and_url_userinfo() {
        let config = OpenSearchConfig::cluster(vec![
            "https://admin:url-secret@node1:9200".to_string(),
            "https://node2:9200".to_string(),
        ])
        .with_basic_auth("admin", "field-secret");
        let debug = format!("{config:?}");
        assert!(
            !debug.contains("url-secret"),
            "URL password leaked: {debug}"
        );
        assert!(!debug.contains("field-secret"), "password leaked: {debug}");
        assert!(debug.contains("https://***@node1:9200"));
        assert!(debug.contains("https://node2:9200"));
    }

    #[test]
    fn redact_url_ignores_at_outside_authority() {
        assert_eq!(
            redact_url_for_logging("https://h:9200/p?x=a@b"),
            "https://h:9200/p?x=a@b"
        );
        assert_eq!(redact_url_for_logging("https://u:p@w@h"), "https://***@h");
    }
}
