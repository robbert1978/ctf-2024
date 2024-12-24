use std::{
    fs::read_to_string,
    sync::{LazyLock, Mutex},
};

use actix_web::{
    cookie::Cookie,
    get, post,
    web::{self, Data},
    Responder,
};
use actix_web_validator::Json;
use rand::distributions::{Alphanumeric, DistString};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::json;
use sqlx::{MySql, Pool};
use uuid::Uuid;
use validator::Validate;

use crate::{
    entity::{Messages, Users},
    request::{Request, RspResult, SESSION},
};

static CONFIG_FOLDER: LazyLock<Mutex<&str>> = LazyLock::new(|| Mutex::new("./config/"));
static COUNTER: LazyLock<Mutex<i32>> = LazyLock::new(|| Default::default());

#[derive(Validate, Deserialize)]
struct AuthParam {
    #[validate(length(max = 32))]
    name: String,
    password: String,
}

#[post("/login")]
async fn login_admin(param: Json<AuthParam>, db: Data<Pool<MySql>>) -> RspResult<impl Responder> {
    login_handler(param, db, true).await
}

#[post("/login")]
async fn login(param: Json<AuthParam>, db: Data<Pool<MySql>>) -> RspResult<impl Responder> {
    login_handler(param, db, false).await
}

async fn login_handler(
    param: Json<AuthParam>,
    db: Data<Pool<MySql>>,
    admin: bool,
) -> RspResult<impl Responder> {
    let ret: Option<Users> =
        sqlx::query_as("SELECT * FROM `users` WHERE `name` = ? AND `password` = ? AND `admin` = ?")
            .bind(&param.name)
            .bind(&param.password)
            .bind(if admin { 1 } else { 0 })
            .fetch_optional(db.as_ref())
            .await?;
    match ret {
        Some(x) => {
            let id = Alphanumeric.sample_string(&mut rand::thread_rng(), 64);
            SESSION.insert(id.clone(), x.id);
            let cookie = Cookie::build("SESSIONID", id)
                .path("/")
                .http_only(true)
                .finish();
            Ok(web::Json(json!({
                "code": 0,
                "message": "ok",
            }))
            .customize()
            .add_cookie(&cookie))
        }
        None => Ok(web::Json(json!({
            "code": 1,
            "message": "invalid user name/password",
        }))
        .customize()),
    }
}

#[post("/register")]
async fn register(param: Json<AuthParam>, db: Data<Pool<MySql>>) -> RspResult<impl Responder> {
    sqlx::query("INSERT INTO `users` (`name`, `password`, `admin`) VALUES (?, ?, 0)")
        .bind(&param.name)
        .bind(&param.password)
        .execute(db.as_ref())
        .await?;
    Ok(web::Json(json!({
        "code": 0,
        "message": "ok",
    })))
}

fn check_sql(s: &str) -> bool {
    let blacklist = vec![
        ";", "INSERT", "SELECT", "UNION", "OR", "\\", " ", "|", "&", "%",
    ];
    for i in blacklist {
        if s.contains(i) {
            return false;
        }
    }
    let re1 = RegexBuilder::new(r"\w+(\(.*\)).*")
        .case_insensitive(true)
        .build()
        .unwrap();
    let re2 = Regex::new(r"\([\s\S]*,[\s\S]*").unwrap();
    if re1.find(s).is_some() || re2.find(s).is_some() {
        return false;
    }
    return true;
}

#[get("/message")]
async fn get_message(req: Request, db: Data<Pool<MySql>>) -> RspResult<impl Responder> {
    let id = match req.id {
        Some(x) => x,
        None => {
            return Ok(web::Json(json!({
                "code": -1,
                "message": "unauthorized",
            })))
        }
    };
    let ret: Option<Messages> =
        sqlx::query_as("SELECT * FROM `messages` WHERE `uid` = ? ORDER BY `id` desc LIMIT 1")
            .bind(id)
            .fetch_optional(db.as_ref())
            .await?;
    Ok(web::Json(json!({
        "code": 0,
        "message": ret.map(|x|x.message).unwrap_or_default(),
    })))
}

#[derive(Validate, Deserialize)]
struct AddMessageParam {
    message: String,
}

#[post("/message")]
async fn add_message(
    req: Request,
    param: Json<AddMessageParam>,
    db: Data<Pool<MySql>>,
) -> RspResult<impl Responder> {
    let id = match req.id {
        Some(x) => x,
        None => {
            return Ok(web::Json(json!({
                "code": -1,
                "message": "unauthorized",
            })))
        }
    };
    if !check_sql(&param.message) {
        return Ok(web::Json(json!({
            "code": 1,
            "message": "invalid message",
        })));
    }

    {
        let mut lock = COUNTER.lock().unwrap();
        if *lock == 9 {
            sqlx::query("UPDATE `users` SET password = ? where id = 1")
                .bind(Uuid::new_v4().hyphenated().to_string())
                .execute(db.as_ref())
                .await?;
            *lock = 0;
            return Ok(web::Json(json!({
                "code": 2,
                "message": "suspicious behavior detected",
            })));
        }
        *lock += 1;
    }

    let _ = sqlx::query(&format!(
        "INSERT INTO `messages` (`uid`,`message`) VALUES ({id},'{}')",
        param.message
    ))
    .execute(db.as_ref())
    .await;
    Ok(web::Json(json!({
        "code": 0,
        "message": "ok",
    })))
}

#[derive(Validate, Deserialize)]
struct ConfigParam {
    eval: String,
}

#[post("/config")]
async fn config(param: Json<ConfigParam>) -> RspResult<impl Responder> {
    // if !req.id.is_some_and(|x| x == 1) {
    //     return Ok(web::Json(json!({
    //         "code": -1,
    //         "message": "unauthorized",
    //     })));
    // }
    let mut engine = rhai::Engine::new();

    engine.register_fn("set_config", |name: &'static str| {
        *CONFIG_FOLDER.lock().unwrap() = name;
    });
    engine.register_fn("get_config", || *CONFIG_FOLDER.lock().unwrap());

    let file = engine.eval::<String>(&param.eval).unwrap();
    let mut ret: Vec<String> = Vec::new();
    for i in file.split(",") {
        let mut path = format!("{}{i}", CONFIG_FOLDER.lock().unwrap());
        println!("{}", path);
        path.retain(|c| c != '\r' && c != '\n' && c != '\0' && c != ' ' && c != '\t');
        if let Ok(x) = read_to_string(path) {
            ret.push(x);
        }
    }

    let ret = ret.join("\n");
    if ret.contains("0ctf") || ret.contains("{") || ret.contains("}") {
        let msg = format!("nonono: {}, {file}", CONFIG_FOLDER.lock().unwrap());
        Ok(web::Json(json!({
            "code": 1,
            "message": msg,
        })))
    } else {
        Ok(web::Json(json!({
            "code": 0,
            "message": "ok",
            "data": ret
        })))
    }
}
