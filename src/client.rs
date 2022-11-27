use serde::Deserialize;

use crate::{error::Result, token::Token};

#[derive(Clone)]
pub struct KeycloakClient {
    pub inner: reqwest::Client,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
}

impl KeycloakClient {
    pub async fn new_token(&self) -> Result<TokenResponse> {
        let token_response = self
            .inner
            .post(&self.token_url)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("grant_type=client_credentials")
            .send()
            .await?
            .json::<TokenResponse>()
            .await?;

        Ok(token_response)
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub token_type: String,
    pub access_token: String,
    pub expires_in: u64,
}

impl From<TokenResponse> for Token {
    fn from(response: TokenResponse) -> Self {
        Self::new(
            &response.token_type,
            &response.access_token,
            response.expires_in,
        )
    }
}
