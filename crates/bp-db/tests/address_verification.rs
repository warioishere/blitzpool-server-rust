// SPDX-License-Identifier: AGPL-3.0-or-later

//! `find_address_verification`: the one onboarding gate of every Team and
//! Blockparty path, a confirmed email or a signature ownership proof.

use bp_common::AddressId;
use bp_db::{find_address_verification, AddressVerification};
use sqlx::PgPool;

const ADDR: &str = "bc1q_address_verification_test";

async fn cleanup(pool: &PgPool) {
    bp_test_support::delete_email_binding(pool, ADDR).await;
    bp_test_support::delete_signature_ownership(pool, ADDR).await;
}

#[tokio::test]
async fn a_confirmed_email_wins_and_a_signature_alone_verifies() {
    let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
        return;
    };
    let a = AddressId::new(ADDR.to_string()).unwrap();
    cleanup(&pool).await;
    let read = || async { find_address_verification(&pool, &a).await.expect("read") };

    assert_eq!(read().await, None, "neither proof: not verified");

    bp_test_support::seed_signature_ownership(&pool, ADDR).await;
    assert_eq!(read().await, Some(AddressVerification::Signature));
    bp_test_support::delete_signature_ownership(&pool, ADDR).await;

    // An unconfirmed email binding proves nothing.
    sqlx::query(
        r#"INSERT INTO pplns_address_email (address, email, "createdAt", "updatedAt")
           VALUES ($1, 'pending@example.test', 1, 1)"#,
    )
    .bind(ADDR)
    .execute(&pool)
    .await
    .expect("unconfirmed email");
    assert_eq!(read().await, None, "an unconfirmed email does not verify");

    bp_test_support::seed_signature_ownership(&pool, ADDR).await;
    bp_test_support::seed_verified_email(&pool, ADDR, "miner@example.test").await;
    assert_eq!(
        read().await,
        Some(AddressVerification::Email("miner@example.test".to_owned())),
        "with both, the email wins: rows keep it"
    );

    cleanup(&pool).await;
}
