use hyper::http::HeaderValue;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Token {
    pub header_value: HeaderValue,
    pub expiration: Instant,
}

impl Token {
    const EXPIRY_DELTA: Duration = Duration::from_secs(10);

    pub fn new(token_type: &str, access_token: &str, expires_in: u64) -> Self {
        Self {
            header_value: HeaderValue::from_str(&format!("{token_type} {access_token}"))
                .expect("Invalid access token"),
            expiration: Instant::now() + Duration::from_secs(expires_in),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expiration
            .checked_duration_since(Instant::now())
            .map(|dur| dur < Self::EXPIRY_DELTA)
            .unwrap_or(true)
    }
}
