mod common;

use axum::http::StatusCode;
use common::*;
use tower::ServiceExt;

#[tokio::test]
async fn test_create_requires_auth() {
    let app = setup_app().await;

    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/bookmarks")
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(axum::body::Body::from("url=https://example.com&title=Test"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/login");
}

#[tokio::test]
async fn test_create_bookmark() {
    let app = setup_app().await;

    let response = register_user(&app, "alice", "password").await;
    let cookie = extract_cookie(&response);

    let response =
        create_bookmark(&app, &cookie, "https://example.com", "Example", None).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/bookmarks/1");
}

#[tokio::test]
async fn test_create_bookmark_has_owner() {
    let app = setup_app().await;

    let response = register_user(&app, "bob", "password").await;
    let cookie = extract_cookie(&response);

    create_bookmark(&app, &cookie, "https://example.com", "Example", None).await;

    let response = app.clone().oneshot(auth_get("/bookmarks/1", &cookie)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_bookmarks() {
    let app = setup_app().await;

    let response = register_user(&app, "carol", "password").await;
    let cookie = extract_cookie(&response);

    create_bookmark(&app, &cookie, "https://example.com", "Example", None).await;

    let response = app.clone().oneshot(auth_get("/bookmarks", &cookie)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_string(response.into_body()).await;
    assert!(body.contains("Example"));
}

#[tokio::test]
async fn test_detail_bookmark() {
    let app = setup_app().await;

    let response = register_user(&app, "dave", "password").await;
    let cookie = extract_cookie(&response);

    create_bookmark(&app, &cookie, "https://example.com", "Example", None).await;

    let response = app.clone().oneshot(auth_get("/bookmarks/1", &cookie)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_string(response.into_body()).await;
    assert!(body.contains("Example"), "Body missing 'Example': {body}");
    assert!(body.contains("example.com"), "Body missing 'example.com': {body}");
}

#[tokio::test]
async fn test_detail_not_found() {
    let app = setup_app().await;

    let response = register_user(&app, "eve", "password").await;
    let cookie = extract_cookie(&response);

    let response = app.clone().oneshot(auth_get("/bookmarks/999", &cookie)).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_owner_can_edit() {
    let app = setup_app().await;

    let response = register_user(&app, "frank", "password").await;
    let cookie = extract_cookie(&response);

    create_bookmark(&app, &cookie, "https://example.com", "Original", None).await;

    let response = app.clone().oneshot(auth_get("/bookmarks/1/edit", &cookie)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(auth_post(
            "/bookmarks/1/edit",
            &cookie,
            "url=https://new-example.com&title=Updated".to_string(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/bookmarks/1");

    let response = app.clone().oneshot(auth_get("/bookmarks/1", &cookie)).await.unwrap();
    let body = body_to_string(response.into_body()).await;
    assert!(body.contains("Updated"), "Body missing 'Updated': {body}");
    assert!(body.contains("new-example.com"), "Body missing 'new-example.com': {body}");
}

#[tokio::test]
async fn test_non_owner_cannot_edit() {
    let app = setup_app().await;

    let response_a = register_user(&app, "alice", "password").await;
    let cookie_a = extract_cookie(&response_a);
    create_bookmark(&app, &cookie_a, "https://example.com", "Alice's", None).await;

    let response_b = register_user(&app, "bob", "password").await;
    let cookie_b = extract_cookie(&response_b);

    let response = app.clone().oneshot(auth_get("/bookmarks/1/edit", &cookie_b)).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_unauthenticated_cannot_edit() {
    let app = setup_app().await;

    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/bookmarks/1/edit")
                .method("GET")
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
async fn test_owner_can_delete() {
    let app = setup_app().await;

    let response = register_user(&app, "grace", "password").await;
    let cookie = extract_cookie(&response);

    create_bookmark(&app, &cookie, "https://example.com", "To Delete", None).await;

    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/bookmarks/1/delete")
                .method("POST")
                .header("cookie", &cookie)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(location, "/bookmarks");

    let response = app.clone().oneshot(auth_get("/bookmarks/1", &cookie)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_non_owner_cannot_delete() {
    let app = setup_app().await;

    let response_a = register_user(&app, "alice", "password").await;
    let cookie_a = extract_cookie(&response_a);
    create_bookmark(&app, &cookie_a, "https://example.com", "Alice's", None).await;

    let response_b = register_user(&app, "bob", "password").await;
    let cookie_b = extract_cookie(&response_b);

    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/bookmarks/1/delete")
                .method("POST")
                .header("cookie", &cookie_b)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_unauthenticated_cannot_delete() {
    let app = setup_app().await;

    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/bookmarks/1/delete")
                .method("POST")
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
async fn test_cross_user_isolation() {
    let app = setup_app().await;

    let response_a = register_user(&app, "alice", "password").await;
    let cookie_a = extract_cookie(&response_a);
    create_bookmark(&app, &cookie_a, "https://example.com", "Alice's", None).await;

    let response_b = register_user(&app, "bob", "password").await;
    let cookie_b = extract_cookie(&response_b);

    let response = app.clone().oneshot(auth_get("/bookmarks/1/edit", &cookie_b)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/bookmarks/1/delete")
                .method("POST")
                .header("cookie", &cookie_b)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response =
        create_bookmark(&app, &cookie_b, "https://bob.example.com", "Bob's", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_bookmarks_with_tags() {
    let app = setup_app().await;

    let response = register_user(&app, "henry", "password").await;
    let cookie = extract_cookie(&response);

    create_bookmark(
        &app,
        &cookie,
        "https://example.com",
        "Tagged Bookmark",
        Some("rust,async"),
    )
    .await;

    let response = app.clone().oneshot(auth_get("/bookmarks/1", &cookie)).await.unwrap();
    let body = body_to_string(response.into_body()).await;

    assert!(body.contains("rust"));
    assert!(body.contains("async"));
}
