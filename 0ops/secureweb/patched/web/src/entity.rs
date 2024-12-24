#[derive(sqlx::FromRow)]
pub struct Users {
    pub id: i32,
    pub name: String,
    pub password: String,
    pub admin: i32,
}

#[derive(sqlx::FromRow)]
pub struct Messages {
    pub id: i32,
    pub uid: i32,
    pub message: String,
}
