mod common;

use axum::http::StatusCode;
use common::*;
use tower::ServiceExt;

#[tokio::test]
async fn test_register_and_login() {
    let app = setup_app().await;

    let response = register_user(&app, "alice", "password123").await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/bookmarks");

    let cookie = extract_cookie(&response);
    assert!(cookie.starts_with("id="));

    let response = app
        .clone()
        .oneshot(auth_get("/bookmarks/new", &cookie))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_login_valid_credentials() {
    let app = setup_app().await;

    register_user(&app, "bob", "secret").await;

    let response = login_user(&app, "bob", "secret").await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = extract_cookie(&response);
    assert!(cookie.starts_with("id="));
}

#[tokio::test]
async fn test_login_wrong_password() {
    let app = setup_app().await;

    register_user(&app, "charlie", "correct").await;

    let response = login_user(&app, "charlie", "wrong").await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_string(response.into_body()).await;
    assert!(body.contains("Invalid credentials"));
}

#[tokio::test]
async fn test_login_nonexistent_user() {
    let app = setup_app().await;

    let response = login_user(&app, "nobody", "password").await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_string(response.into_body()).await;
    assert!(body.contains("Invalid credentials"));
}

#[tokio::test]
async fn test_duplicate_username() {
    let app = setup_app().await;

    register_user(&app, "dave", "password1").await;

    let response = register_user(&app, "dave", "password2").await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_string(response.into_body()).await;
    assert!(body.contains("Username already taken"));
}

#[tokio::test]
async fn test_passwords_must_match() {
    let app = setup_app().await;

    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/register")
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from(
                    "username=eve&password=abc&confirm_password=xyz",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_string(response.into_body()).await;
    assert!(body.contains("Passwords do not match"));
}

#[tokio::test]
async fn test_logout_clears_session() {
    let app = setup_app().await;

    let response = register_user(&app, "frank", "password").await;
    let cookie = extract_cookie(&response);

    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/logout")
                .method("GET")
                .header("cookie", &cookie)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/login");
}

#[tokio::test]
async fn test_session_persists_across_requests() {
    let app = setup_app().await;

    let response = register_user(&app, "grace", "password").await;
    let cookie = extract_cookie(&response);

    let response = app.clone().oneshot(auth_get("/bookmarks/new", &cookie)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app.clone().oneshot(auth_get("/bookmarks/new", &cookie)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
