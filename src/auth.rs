use futures_util::Future;
use hyper::{header::AUTHORIZATION, http::HeaderValue, Request};
use parking_lot::RwLock;
use std::{
    fmt,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tracing::debug;

use crate::{
    client::{self, KeycloakClient},
    error::Result,
    token::Token,
};

#[derive(Clone)]
pub struct KeycloakAuth {
    inner: Arc<RwLock<KeycloakAuthInner>>,
}

impl KeycloakAuth {
    pub fn new(
        server_url: String,
        realm: String,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(KeycloakAuthInner::new(
                client::KeycloakClient {
                    inner: reqwest::Client::new(),
                    token_url: format!("{server_url}/realms/{realm}/protocol/openid-connect/token"),
                    client_id,
                    client_secret,
                },
            ))),
        }
    }

    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if self.inner.read().can_skip_poll_ready() {
            return Poll::Ready(Ok(()));
        }

        self.inner.write().poll_ready(cx)
    }

    pub fn update_request<T>(&mut self, req: &mut Request<T>) {
        req.headers_mut()
            .insert(AUTHORIZATION, self.inner.read().header_value());
    }
}

struct KeycloakAuthInner {
    state: State,
    client: KeycloakClient,
}

impl KeycloakAuthInner {
    pub fn new(client: KeycloakClient) -> Self {
        Self {
            state: State::NotFetched,
            client,
        }
    }

    #[inline]
    pub fn can_skip_poll_ready(&self) -> bool {
        matches!(self.state, State::Fetched { ref token } if !token.is_expired())
    }

    #[inline]
    pub fn header_value(&self) -> HeaderValue {
        match self.state {
            State::Fetched { ref token } => token.header_value.clone(),
            State::Refetching { ref token, .. } => token.header_value.clone(),
            _ => unreachable!("invalid state: {:?}", self.state),
        }
    }

    #[inline]
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            match self.state {
                State::NotFetched => {
                    self.state = {
                        let oauth_client = self.client.clone();

                        State::Fetching {
                            fut: Box::pin(
                                async move { oauth_client.new_token().await.map(Into::into) },
                            ),
                        }
                    };
                }
                State::Fetching { ref mut fut } => match ready!(fut.as_mut().poll(cx)) {
                    Ok(token) => {
                        debug!("new {:?}", token);
                        self.state = State::Fetched { token };
                        return Poll::Ready(Ok(()));
                    }
                    Err(err) => {
                        return Poll::Ready(Err(err));
                    }
                },
                State::Refetching { ref mut fut, .. } => match ready!(fut.as_mut().poll(cx)) {
                    Ok(token) => {
                        debug!("refreshed {:?}", token);
                        self.state = State::Fetched { token };
                        return Poll::Ready(Ok(()));
                    }
                    Err(err) => {
                        return Poll::Ready(Err(err));
                    }
                },
                State::Fetched { ref token } => {
                    if !token.is_expired() {
                        return Poll::Ready(Ok(()));
                    }

                    self.state = {
                        let oauth_client = self.client.clone();

                        State::Refetching {
                            fut: Box::pin(
                                async move { oauth_client.new_token().await.map(Into::into) },
                            ),
                            token: token.clone(),
                        }
                    };
                }
            }
        }
    }
}

pub enum State {
    NotFetched,
    Fetching {
        fut: Pin<Box<dyn Future<Output = Result<Token>>>>,
    },
    Refetching {
        fut: Pin<Box<dyn Future<Output = Result<Token>>>>,
        token: Token,
    },
    Fetched {
        token: Token,
    },
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFetched => write!(f, "NotFetched"),
            Self::Fetching { .. } => write!(f, "Fetching"),
            Self::Refetching { .. } => write!(f, "Refetching"),
            Self::Fetched { .. } => write!(f, "Fetched"),
        }
    }
}
