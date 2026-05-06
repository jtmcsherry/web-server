use axum::body::Body;
use axum::http::Request;
use sqlx::SqlitePool;
use tower::ServiceExt;
use web_server::{build_test_router, hash_password};

/// Creates a fresh in-memory database with schema applied.
pub async fn setup_db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::raw_sql(include_str!("../schema.sql"))
        .execute(&pool)
        .await
        .unwrap();
    pool
}

/// Builds a test-ready router with an in-memory session store.
pub async fn setup_app() -> axum::Router {
    let pool = setup_db().await;
    build_test_router(pool).await
}

/// Seeds a user directly into the database (bypassing registration).
pub async fn seed_user(pool: &SqlitePool, username: &str, password: &str) -> i64 {
    let hash = hash_password(password).await;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO "user" (username, password_hash) VALUES (?, ?) RETURNING id"#,
    )
    .bind(username)
    .bind(&hash)
    .fetch_one(pool)
    .await
    .unwrap();
    id
}

/// Extracts the session cookie value from a response's Set-Cookie header.
pub fn extract_cookie(response: &axum::http::Response<Body>) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find(|h| h.to_str().unwrap().starts_with("id="))
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(';').next())
        .map(|s| s.to_string())
        .expect("No session cookie found in response")
}

/// Helper to register a user and return the response (with session cookie if successful).
pub async fn register_user(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/register")
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password={}&confirm_password={}",
                    url::form_urlencoded::byte_serialize(username.as_bytes()).collect::<String>(),
                    url::form_urlencoded::byte_serialize(password.as_bytes()).collect::<String>(),
                    url::form_urlencoded::byte_serialize(password.as_bytes()).collect::<String>(),
                )))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper to login a user and return the response (with session cookie if successful).
pub async fn login_user(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> axum::http::Response<Body> {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password={}",
                    url::form_urlencoded::byte_serialize(username.as_bytes()).collect::<String>(),
                    url::form_urlencoded::byte_serialize(password.as_bytes()).collect::<String>(),
                )))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Helper to create a bookmark as an authenticated user.
pub async fn create_bookmark(
    app: &axum::Router,
    cookie: &str,
    url: &str,
    title: &str,
    tags: Option<&str>,
) -> axum::http::Response<Body> {
    let mut body = format!(
        "url={}&title={}",
        url::form_urlencoded::byte_serialize(url.as_bytes()).collect::<String>(),
        url::form_urlencoded::byte_serialize(title.as_bytes()).collect::<String>(),
    );
    if let Some(t) = tags {
        body.push_str(&format!(
            "&tags={}",
            url::form_urlencoded::byte_serialize(t.as_bytes()).collect::<String>()
        ));
    }

    app.clone()
        .oneshot(
            Request::builder()
                .uri("/bookmarks")
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", cookie)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Build an authenticated GET request.
pub fn auth_get(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .method("GET")
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

/// Build an authenticated POST request.
pub fn auth_post(uri: &str, cookie: &str, body: String) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", cookie)
        .body(Body::from(body))
        .unwrap()
}

/// Collect the body into a string for assertions.
pub async fn body_to_string(body: Body) -> String {
    use http_body_util::BodyExt;
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}
