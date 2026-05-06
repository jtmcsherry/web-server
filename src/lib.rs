use std::collections::HashMap;
use std::sync::Arc;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    Router,
    extract::{Form, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_login::{AuthManagerLayerBuilder, AuthSession, AuthUser, AuthnBackend, AuthzBackend};
use minijinja::{Environment, context};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use time::Duration;
use tower_sessions::Expiry;
use tower_sessions_sqlx_store::SqliteStore;

// ─── Data models ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub id: i64,
    pub user_id: i64,
    pub url: String,
    pub title: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBookmarkForm {
    pub url: String,
    pub title: String,
    pub tags: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    pub username: String,
    pub password: String,
    pub confirm_password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBookmarkForm {
    pub url: String,
    pub title: String,
    pub tags: Option<String>,
}

// ─── Permission system ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Permission {
    DeleteBookmark,
    UpdateBookmark,
}

// ─── Auth backend ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Backend {
    pub db: SqlitePool,
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.password_hash.as_bytes()
    }
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = LoginForm;
    type Error = sqlx::Error;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let Some(user): Option<User> = sqlx::query_as(
            r#"SELECT id, username, password_hash FROM "user" WHERE username = ?"#,
        )
        .bind(&creds.username)
        .fetch_optional(&self.db)
        .await?
        else {
            return Ok(None);
        };

        let parsed_hash = PasswordHash::new(&user.password_hash).expect("invalid stored hash");
        let result = Argon2::default().verify_password(creds.password.as_bytes(), &parsed_hash);

        if result.is_ok() {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    async fn get_user(
        &self,
        user_id: &<Self::User as AuthUser>::Id,
    ) -> Result<Option<Self::User>, Self::Error> {
        sqlx::query_as(
            r#"SELECT id, username, password_hash FROM "user" WHERE id = ?"#,
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
    }
}

impl AuthzBackend for Backend {
    type Permission = Permission;

    async fn get_user_permissions(
        &self,
        _user: &Self::User,
    ) -> Result<std::collections::HashSet<Self::Permission>, Self::Error> {
        Ok(std::collections::HashSet::new())
    }
}

// ─── Application state ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub templates: Arc<Environment<'static>>,
}

// ─── Helpers ───────────────────────────────────────────────────────────────

pub async fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("failed to hash password")
        .to_string()
}

fn database_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Html("database error".to_string())).into_response()
}

fn render(env: &Environment, name: &str, ctx: minijinja::Value) -> Response {
    match env.get_template(name).and_then(|t| t.render(ctx)) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            eprintln!("template error: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, Html("template error".to_string())).into_response()
        }
    }
}

// ─── Templating ────────────────────────────────────────────────────────────

pub fn build_templates() -> Environment<'static> {
    let mut env = Environment::new();
    env.add_template("base.html", include_str!("../templates/base.html"))
        .unwrap();
    env.add_template("list.html", include_str!("../templates/list.html"))
        .unwrap();
    env.add_template("detail.html", include_str!("../templates/detail.html"))
        .unwrap();
    env.add_template("new.html", include_str!("../templates/new.html"))
        .unwrap();
    env.add_template("login.html", include_str!("../templates/login.html"))
        .unwrap();
    env.add_template("register.html", include_str!("../templates/register.html"))
        .unwrap();
    env.add_template("edit.html", include_str!("../templates/edit.html"))
        .unwrap();
    env
}

// ─── Database queries ──────────────────────────────────────────────────────

pub async fn get_all_bookmarks(pool: &SqlitePool) -> sqlx::Result<Vec<Bookmark>> {
    let bookmarks = sqlx::query_as::<_, (i64, i64, String, String)>(
        "select id, user_id, url, title from bookmark order by id",
    )
    .fetch_all(pool)
    .await?;

    let links = sqlx::query_as::<_, (i64, i64)>(
        "SELECT bookmark_id, tag_id FROM bookmark_tag",
    )
    .fetch_all(pool)
    .await?;

    let tags = sqlx::query_as::<_, (i64, String)>(
        r#"SELECT id, name FROM tag WHERE id IN (SELECT tag_id FROM bookmark_tag)"#,
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect::<HashMap<_, _>>();

    let mut tags_by_bookmark: HashMap<i64, Vec<String>> = HashMap::new();
    for (bookmark_id, tag_id) in &links {
        if let Some(name) = tags.get(tag_id) {
            tags_by_bookmark.entry(*bookmark_id).or_default().push(name.clone());
        }
    }

    let bookmarks: Vec<_> = bookmarks
        .into_iter()
        .map(|(id, user_id, url, title)| Bookmark {
            id,
            user_id,
            url,
            title,
            tags: tags_by_bookmark.remove(&id).unwrap_or_default(),
        })
        .collect();

    Ok(bookmarks)
}

pub async fn get_bookmark_from_id(pool: &SqlitePool, id: i64) -> sqlx::Result<Option<Bookmark>> {
    let Some((id, user_id, url, title)) =
        sqlx::query_as::<_, (i64, i64, String, String)>(
            "select id, user_id, url, title from bookmark where id = ?",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };

    let tags = sqlx::query_scalar::<_, String>(
        "select tag.name from tag, bookmark_tag bt where tag.id = bt.tag_id and bt.bookmark_id = ?",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;

    Ok(Some(Bookmark { id, user_id, url, title, tags }))
}

pub async fn create_bookmark_impl(
    pool: &SqlitePool,
    user_id: i64,
    url: String,
    title: String,
    tags: Vec<String>,
) -> sqlx::Result<i64> {
    let bookmark_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO bookmark (user_id, url, title) VALUES (?, ?, ?) RETURNING id",
    )
    .bind(user_id)
    .bind(&url)
    .bind(&title)
    .fetch_one(pool)
    .await?;

    if !tags.is_empty() {
        let placeholders = vec!["(?)"; tags.len()].join(", ");
        let query_text = format!("insert or ignore into tag (name) values {placeholders}");
        let insert_query = tags.iter().fold(sqlx::query(&query_text), |q, tag| q.bind(tag));
        insert_query.execute(pool).await?;

        let placeholders = vec!["?"; tags.len()].join(", ");
        let link_tags = format!(
            "INSERT INTO bookmark_tag (bookmark_id, tag_id) SELECT ?, id FROM tag WHERE name IN ({placeholders})"
        );
        let mut q = sqlx::query(&link_tags).bind(bookmark_id);
        for tag in tags {
            q = q.bind(tag);
        }
        q.execute(pool).await?;
    }

    Ok(bookmark_id)
}

// ─── Handlers ──────────────────────────────────────────────────────────────

async fn list_bookmarks(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    let Ok(bookmarks) = get_all_bookmarks(&state.db).await else {
        return database_error();
    };
    render(&state.templates, "list.html", context! { bookmarks, user => auth.user })
}

async fn new_bookmark_form(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    render(&state.templates, "new.html", context! { user => auth.user })
}

async fn create_bookmark(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Form(form): Form<CreateBookmarkForm>,
) -> Response {
    let Some(user) = auth.user else {
        return Redirect::to("/login").into_response();
    };

    let tags: Vec<String> = form
        .tags
        .unwrap_or_default()
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    let Ok(id) = create_bookmark_impl(&state.db, user.id, form.url, form.title, tags).await else {
        return database_error();
    };

    Redirect::to(&format!("/bookmarks/{id}")).into_response()
}

async fn get_bookmark(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<i64>,
) -> Response {
    match get_bookmark_from_id(&state.db, id).await {
        Err(_) => database_error(),
        Ok(Some(bm)) => {
            let is_owner = auth.user.as_ref().map(|u| u.id) == Some(bm.user_id);
            render(&state.templates, "detail.html", context! { bookmark => bm, is_owner, user => auth.user })
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            render(&state.templates, "404.html", context! { user => auth.user }),
        )
            .into_response(),
    }
}

async fn delete_bookmark(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<i64>,
) -> Response {
    let Some(user) = auth.user else {
        return Redirect::to("/login").into_response();
    };

    let Ok(Some(bm)) = get_bookmark_from_id(&state.db, id).await else {
        return (StatusCode::NOT_FOUND, Html("Bookmark not found")).into_response();
    };

    if bm.user_id != user.id {
        return (
            StatusCode::FORBIDDEN,
            Html("You can only delete your own bookmarks"),
        )
            .into_response();
    }

    if sqlx::query("delete from bookmark_tag where bookmark_id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .is_ok()
        && sqlx::query("delete from bookmark where id = ?")
            .bind(id)
            .execute(&state.db)
            .await
            .is_ok()
    {
        return Redirect::to("/bookmarks").into_response();
    }

    database_error()
}

async fn edit_bookmark_form(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<i64>,
) -> Response {
    let Some(user) = auth.user.clone() else {
        return Redirect::to("/login").into_response();
    };

    let Ok(Some(bm)) = get_bookmark_from_id(&state.db, id).await else {
        return (StatusCode::NOT_FOUND, Html("Bookmark not found")).into_response();
    };

    if bm.user_id != user.id {
        return (
            StatusCode::FORBIDDEN,
            Html("You can only edit your own bookmarks"),
        )
            .into_response();
    }

    render(&state.templates, "edit.html", context! { bookmark => bm, user => auth.user })
}

async fn update_bookmark(
    State(state): State<AppState>,
    auth: AuthSession<Backend>,
    Path(id): Path<i64>,
    Form(form): Form<UpdateBookmarkForm>,
) -> Response {
    let Some(user) = auth.user else {
        return Redirect::to("/login").into_response();
    };

    let Ok(Some(bm)) = get_bookmark_from_id(&state.db, id).await else {
        return (StatusCode::NOT_FOUND, Html("Bookmark not found")).into_response();
    };

    if bm.user_id != user.id {
        return (
            StatusCode::FORBIDDEN,
            Html("You can only update your own bookmarks"),
        )
            .into_response();
    }

    let tags: Vec<String> = form
        .tags
        .unwrap_or_default()
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    if sqlx::query("delete from bookmark_tag where bookmark_id = ?")
        .bind(id)
        .execute(&state.db)
        .await
        .is_ok()
    {
        if sqlx::query("update bookmark set url = ?, title = ? where id = ?")
            .bind(&form.url)
            .bind(&form.title)
            .bind(id)
            .execute(&state.db)
            .await
            .is_ok()
        {
            if !tags.is_empty() {
                let placeholders = vec!["(?)"; tags.len()].join(", ");
                let query_text =
                    format!("insert or ignore into tag (name) values {placeholders}");
                let insert_query =
                    tags.iter().fold(sqlx::query(&query_text), |q, tag| q.bind(tag));
                let _ = insert_query.execute(&state.db).await;

                let placeholders = vec!["?"; tags.len()].join(", ");
                let link_tags = format!(
                    "INSERT INTO bookmark_tag (bookmark_id, tag_id) SELECT ?, id FROM tag WHERE name IN ({placeholders})"
                );
                let mut q = sqlx::query(&link_tags).bind(id);
                for tag in tags {
                    q = q.bind(tag);
                }
                let _ = q.execute(&state.db).await;
            }
            return Redirect::to(&format!("/bookmarks/{id}")).into_response();
        }
    }

    database_error()
}

async fn login_form(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    render(&state.templates, "login.html", context! { user => auth.user })
}

async fn login_handler(
    State(state): State<AppState>,
    mut auth: AuthSession<Backend>,
    Form(form): Form<LoginForm>,
) -> Response {
    match auth.authenticate(form).await {
        Ok(Some(user)) => {
            if auth.login(&user).await.is_err() {
                return database_error();
            }
            Redirect::to("/bookmarks").into_response()
        }
        Ok(None) => render(
            &state.templates,
            "login.html",
            context! { error => "Invalid credentials", user => auth.user },
        ),
        Err(_) => database_error(),
    }
}

async fn logout_handler(mut auth: AuthSession<Backend>) -> Response {
    let _ = auth.logout().await;
    Redirect::to("/login").into_response()
}

async fn register_form(State(state): State<AppState>, auth: AuthSession<Backend>) -> Response {
    render(&state.templates, "register.html", context! { user => auth.user })
}

async fn register_handler(
    State(state): State<AppState>,
    mut auth: AuthSession<Backend>,
    Form(form): Form<RegisterForm>,
) -> Response {
    if form.password != form.confirm_password {
        return render(
            &state.templates,
            "register.html",
            context! { error => "Passwords do not match", user => auth.user },
        );
    }

    let hash = hash_password(&form.password).await;

    if sqlx::query(
        r#"INSERT INTO "user" (username, password_hash) VALUES (?, ?)"#,
    )
    .bind(&form.username)
    .bind(&hash)
    .execute(&state.db)
    .await
    .is_ok()
    {
        if let Ok(user) = sqlx::query_as::<_, User>(
            r#"SELECT id, username, password_hash FROM "user" WHERE username = ?"#,
        )
        .bind(&form.username)
        .fetch_one(&state.db)
        .await
        {
            if auth.login(&user).await.is_ok() {
                return Redirect::to("/bookmarks").into_response();
            }
        }
        return database_error();
    }

    render(
        &state.templates,
        "register.html",
        context! { error => "Username already taken", user => auth.user },
    )
}

// ─── Router builder ────────────────────────────────────────────────────────

fn build_router_inner(
    state: AppState,
    auth_layer: axum_login::AuthManagerLayer<Backend, SqliteStore>,
) -> Router {
    Router::new()
        .route("/bookmarks", get(list_bookmarks).post(create_bookmark))
        .route("/bookmarks/new", get(new_bookmark_form))
        .route("/bookmarks/{id}", get(get_bookmark))
        .route("/bookmarks/{id}/delete", post(delete_bookmark))
        .route(
            "/bookmarks/{id}/edit",
            get(edit_bookmark_form).post(update_bookmark),
        )
        .route("/login", get(login_form).post(login_handler))
        .route("/register", get(register_form).post(register_handler))
        .route("/logout", get(logout_handler))
        .layer(auth_layer)
        .with_state(state)
}

/// Production router builder — caller provides the session store.
pub fn build_router(pool: SqlitePool, session_store: SqliteStore) -> Router {
    let session_layer = tower_sessions::SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));

    let backend = Backend { db: pool.clone() };
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    let state = AppState {
        db: pool,
        templates: Arc::new(build_templates()),
    };

    build_router_inner(state, auth_layer)
}

/// Test router builder — creates its own in-memory session store.
pub async fn build_test_router(pool: SqlitePool) -> Router {
    let session_store = SqliteStore::new(pool.clone());
    session_store
        .migrate()
        .await
        .expect("Cannot migrate session store");

    let session_layer = tower_sessions::SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));

    let backend = Backend { db: pool.clone() };
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    let state = AppState {
        db: pool,
        templates: Arc::new(build_templates()),
    };

    build_router_inner(state, auth_layer)
}
