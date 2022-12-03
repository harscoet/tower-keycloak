#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid URL: {0}")]
    ParseUrl(#[from] url::ParseError),
    #[error("server error when fetching token: status {status_code} - {response_text}")]
    FetchToken {
        status_code: u16,
        response_text: String,
    },
    #[error("http request error: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("http request with middleware error: {0}")]
    HttpRequestWithMiddleware(#[from] reqwest_middleware::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
