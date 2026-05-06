use argon2::{Argon2, PasswordHash, PasswordVerifier};
use web_server::hash_password;

#[tokio::test]
async fn test_hash_password_is_different_each_time() {
    let hash1 = hash_password("same_password").await;
    let hash2 = hash_password("same_password").await;

    assert_ne!(hash1, hash2);
}

#[tokio::test]
async fn test_verify_password_correct() {
    let hash = hash_password("correct_password").await;
    let parsed_hash = PasswordHash::new(&hash).unwrap();

    let result = Argon2::default().verify_password(b"correct_password", &parsed_hash);
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_verify_password_incorrect() {
    let hash = hash_password("correct_password").await;
    let parsed_hash = PasswordHash::new(&hash).unwrap();

    let result = Argon2::default().verify_password(b"wrong_password", &parsed_hash);
    assert!(result.is_err());
}
