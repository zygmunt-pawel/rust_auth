mod common;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn library_migrator_applies_cleanly() {
    let (_c, pool) = common::pg_container_no_migrate().await;
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

    // P5: partial index supporting verify_by_code's live-row subselect.
    let magic_indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname::text FROM pg_indexes
         WHERE schemaname = 'public' AND tablename = 'magic_links'
         ORDER BY indexname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        magic_indexes.contains(&"idx_magic_links_email_live_code".to_string()),
        "missing idx_magic_links_email_live_code; got {magic_indexes:?}"
    );

    // Confirm the partial index has the expected predicate (planner only uses
    // it when the WHERE clause matches both predicates).
    let predicate: Option<String> = sqlx::query_scalar(
        "SELECT pg_get_expr(indpred, indrelid)
         FROM pg_index
         WHERE indexrelid = 'idx_magic_links_email_live_code'::regclass",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    let predicate = predicate.expect("partial index must have a predicate");
    assert!(
        predicate.contains("used_at") && predicate.contains("code_burned_at"),
        "partial index predicate must filter used_at and code_burned_at; got: {predicate}"
    );
}
