use futures_util::future::MapErr;
use futures_util::TryFutureExt;
use std::task::{ready, Context, Poll};
use tower_service::Service;
use tracing::debug;

use crate::{error, KeycloakAuth};

#[derive(Clone)]
pub struct KeycloakService<T> {
    inner: T,
    auth: KeycloakAuth,
}

impl<T> KeycloakService<T> {
    pub fn new(inner: T, auth: KeycloakAuth) -> Self {
        Self { inner, auth }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error<E> {
    #[error("inner service error: {0}")]
    Service(E),
    #[error("keycloak error: {0}")]
    Keycloak(error::Error),
}

impl<T, ReqBody> Service<hyper::Request<ReqBody>> for KeycloakService<T>
where
    T: Service<hyper::Request<ReqBody>>,
{
    type Response = T::Response;
    type Error = Error<T::Error>;
    type Future = MapErr<T::Future, fn(T::Error) -> Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match ready!(self.auth.poll_ready(cx)) {
            Ok(()) => self.inner.poll_ready(cx).map_err(Error::Service),
            Err(err) => {
                debug!(?err);
                Poll::Ready(Err(Error::Keycloak(err)))
            }
        }
    }

    fn call(&mut self, mut req: hyper::Request<ReqBody>) -> Self::Future {
        self.auth.update_request(&mut req);
        self.inner.call(req).map_err(Error::Service)
    }
}
