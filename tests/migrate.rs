#[sqlx::test(migrations = false)]
async fn library_migrator_applies_cleanly(pool: sqlx::PgPool) {
    auth_rust::store::migrator()
        .run(&pool)
        .await
        .expect("migrations apply");

    // Sanity: tables exist.
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables
         WHERE table_schema = 'public' AND table_name IN ('users','magic_links','sessions')
         ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        tables,
        vec!["magic_links".to_string(), "sessions".into(), "users".into()]
    );
}
