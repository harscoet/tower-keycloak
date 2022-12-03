use hyper::{http::HeaderValue, HeaderMap};
use reqwest::Url;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use reqwest_tracing::{SpanBackendWithUrl, TracingMiddleware};
use serde::Deserialize;
use std::time::Duration;
use tracing::instrument;

use crate::{auth::TokenResponseFuture, error::Result, token::Token, Error};

#[derive(Clone)]
pub struct KeycloakClient {
    pub inner: ClientWithMiddleware,
    pub token_url: Url,
    pub client_id: String,
    pub client_secret: String,
}

impl KeycloakClient {
    pub fn new(token_url: String, client_id: String, client_secret: String) -> Result<Self> {
        let mut default_headers = HeaderMap::new();

        default_headers.insert(
            "Content-Type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let inner_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .default_headers(default_headers)
            .build()?;

        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);

        let client = ClientBuilder::new(inner_client)
            .with(TracingMiddleware::<SpanBackendWithUrl>::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Ok(Self {
            inner: client,
            token_url: Url::parse(&token_url)?,
            client_id,
            client_secret,
        })
    }

    #[instrument(skip(self))]
    pub async fn fetch_token(&self) -> Result<Token> {
        let response = self
            .inner
            .post(self.token_url.clone())
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .body("grant_type=client_credentials")
            .send()
            .await?;

        let status = response.status();

        if !status.is_success() {
            let status_code = response.status().as_u16();
            let response_text = response.text().await?;

            return Err(Error::FetchToken {
                status_code,
                response_text,
            });
        }

        let token_response = response.json::<TokenResponse>().await?;

        let token = Token::new(
            &token_response.token_type,
            &token_response.access_token,
            token_response.expires_in,
        );

        Ok(token)
    }

    pub fn fetch_token_boxed(&self) -> TokenResponseFuture {
        let client = self.clone();
        Box::pin(async move { client.fetch_token().await })
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub token_type: String,
    pub access_token: String,
    pub expires_in: u64,
}
