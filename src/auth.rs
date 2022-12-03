use futures_util::future::BoxFuture;
use hyper::{header::AUTHORIZATION, http::HeaderValue, Request};
use parking_lot::RwLock;
use std::{
    fmt,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tracing::trace;

use crate::{
    client::{self, KeycloakClient},
    error::Result,
    sync::RefGuard,
    token::Token,
};

pub type TokenResponseFuture = BoxFuture<'static, Result<Token>>;

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
    ) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(RwLock::new(KeycloakAuthInner::new(
                client::KeycloakClient::new(
                    format!("{server_url}/realms/{realm}/protocol/openid-connect/token"),
                    client_id,
                    client_secret,
                )?,
            ))),
        })
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
                    trace!("State::NotFetched");

                    self.state = {
                        State::Fetching {
                            fut: RefGuard::new(self.client.fetch_token_boxed()),
                        }
                    };
                }
                State::Fetching { ref mut fut } => match ready!(fut.get_mut().as_mut().poll(cx)) {
                    Ok(token) => {
                        trace!("State::Fetching {:?}", token);
                        self.state = State::Fetched { token };
                        return Poll::Ready(Ok(()));
                    }
                    Err(err) => {
                        self.state = State::NotFetched;
                        return Poll::Ready(Err(err));
                    }
                },
                State::Refetching { ref mut fut, .. } => {
                    match ready!(fut.get_mut().as_mut().poll(cx)) {
                        Ok(token) => {
                            trace!("State::Refetching {:?}", token);
                            self.state = State::Fetched { token };
                            return Poll::Ready(Ok(()));
                        }
                        Err(err) => {
                            self.state = State::NotFetched;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                State::Fetched { ref token } => {
                    trace!("State::Fetched (token is expired)");

                    self.state = {
                        State::Refetching {
                            fut: RefGuard::new(self.client.fetch_token_boxed()),
                            token: token.clone(),
                        }
                    };
                }
            }
        }
    }
}

pub(crate) enum State {
    NotFetched,
    Fetching {
        fut: RefGuard<TokenResponseFuture>,
    },
    Refetching {
        fut: RefGuard<TokenResponseFuture>,
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
