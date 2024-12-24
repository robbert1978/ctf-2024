use std::{
    fmt::{self, Display},
    future::{ready, Ready},
    sync::LazyLock,
};

use actix_web::{
    body::MessageBody,
    dev::{Payload, ServiceRequest, ServiceResponse},
    http::StatusCode,
    middleware::Next,
    FromRequest, HttpMessage, HttpRequest, HttpResponse,
};
use dashmap::DashMap;

// mock a session
pub static SESSION: LazyLock<DashMap<String, i32>> = LazyLock::new(|| Default::default());

pub type RspResult<T> = Result<T, ResponseError>;

#[derive(Debug)]
pub struct ResponseError(anyhow::Error);

impl Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl actix_web::ResponseError for ResponseError {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).finish()
    }
}

impl<T> From<T> for ResponseError
where
    T: Into<anyhow::Error>,
{
    fn from(t: T) -> Self {
        Self(t.into())
    }
}

pub struct Request {
    pub id: Option<i32>,
}

impl FromRequest for Request {
    type Error = actix_web::Error;
    type Future = Ready<Result<Request, actix_web::Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(
            req.extensions_mut()
                .remove::<Self>()
                .ok_or(actix_web::error::ErrorBadGateway(anyhow::anyhow!(
                    "Request is not parsed"
                ))),
        )
    }
}

pub async fn auth_checker(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let id = if let Some(x) = req.cookie("SESSIONID") {
        SESSION.get(x.value()).map(|x| *x)
    } else {
        None
    };
    req.extensions_mut().insert(Request { id });
    next.call(req).await
}

pub async fn admin_checker(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    // if let Some(x) = req.headers().get("x-forwarded-for") {
    //     if x.to_str().unwrap() != "127.0.0.1" {
    //         Err(actix_web::error::ErrorForbidden("Forbidden"))
    //     } else {
    //         next.call(req).await
    //     }
    // } else {
    //     Err(actix_web::error::ErrorForbidden("Forbidden"))
    // }
    next.call(req).await
}
