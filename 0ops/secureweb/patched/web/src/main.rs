use std::env;

use actix_web::{
    middleware::{from_fn, Logger},
    web::{self, scope, Data},
    App, HttpServer, Responder,
};
use env_logger::Env;
use request::{admin_checker, auth_checker};
use sqlx::MySqlPool;

mod api;
mod entity;
mod request;

async fn index() -> impl Responder {
    "I am too lazy to write a frontend :)"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    let db = MySqlPool::connect(&env::var("DSN").unwrap()).await.unwrap();
    let db = Data::new(db);

    HttpServer::new(move || {
        App::new()
            // .service(
            //     scope("/api")
            //         .service(api::login)
            //         .service(api::register)
            //         .service(api::add_message)
            //         .service(api::get_message),
            // )
            .service(
                scope("/admin")
                    .service(api::login_admin)
                    .service(api::config)
                    .wrap(from_fn(admin_checker)),
            )
            .service(web::resource("/").route(web::get().to(index)))
            .wrap(Logger::default())
            // .wrap(from_fn(auth_checker))
            .app_data(db.clone())
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
