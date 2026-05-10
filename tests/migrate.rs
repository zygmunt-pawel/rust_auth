#[sqlx::test(migrations = false)]
async fn library_migrator_applies_cleanly(pool: sqlx::PgPool) {
    auth_rust::store::migrator()
        .run(&pool)
        .await
        .expect("migrations apply");

    // Sanity: tables exist.
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables
         WHERE table_schema = 'public'
           AND table_name IN ('users','magic_links','sessions','auth_identities')
         ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        tables,
        vec![
            "auth_identities".to_string(),
            "magic_links".into(),
            "sessions".into(),
            "users".into(),
        ]
    );

    // auth_identities indexes + unique constraint exist.
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname::text FROM pg_indexes
         WHERE schemaname = 'public' AND tablename = 'auth_identities'
         ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        indexes.contains(&"idx_auth_identities_user".to_string()),
        "missing idx_auth_identities_user; got {indexes:?}"
    );

    let constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname::text FROM pg_constraint
         WHERE conrelid = 'auth_identities'::regclass
         ORDER BY conname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        constraints.contains(&"auth_identities_provider_subject_uniq".to_string()),
        "missing UNIQUE(provider, subject); got {constraints:?}"
    );
}
