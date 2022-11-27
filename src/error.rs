#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("http error")]
    Http(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
