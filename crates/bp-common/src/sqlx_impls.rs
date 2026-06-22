// SPDX-License-Identifier: AGPL-3.0-or-later

//! `sqlx::Type` / `Decode` / `Encode` for Postgres on `Sats` / `AddressId` /
//! `MiningMode`. Gated behind the `sqlx` Cargo feature.
//!
//! Lives in `bp-common` (not `bp-db`) to satisfy the Rust orphan rule —
//! you can only `impl ForeignTrait for ForeignType` from the crate that
//! owns the type.

use std::str::FromStr;

use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, Postgres, Type};

use super::{AddressId, MiningMode, Sats};

// ----- Sats <-> BIGINT -----

impl Type<Postgres> for Sats {
    fn type_info() -> PgTypeInfo {
        <i64 as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <i64 as Type<Postgres>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Postgres> for Sats {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let v = <i64 as Decode<Postgres>>::decode(value)?;
        Ok(Sats(v))
    }
}

impl<'q> Encode<'q, Postgres> for Sats {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <i64 as Encode<Postgres>>::encode_by_ref(&self.0, buf)
    }
}

// ----- AddressId <-> VARCHAR -----

impl Type<Postgres> for AddressId {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <String as Type<Postgres>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Postgres> for AddressId {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let s = <String as Decode<Postgres>>::decode(value)?;
        AddressId::new(s).map_err(|e| Box::new(e) as BoxDynError)
    }
}

impl<'q> Encode<'q, Postgres> for AddressId {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&str as Encode<Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

// ----- MiningMode <-> VARCHAR (kebab-case) -----

impl Type<Postgres> for MiningMode {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <String as Type<Postgres>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Postgres> for MiningMode {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        MiningMode::from_str(s).map_err(|e| Box::new(e) as BoxDynError)
    }
}

impl<'q> Encode<'q, Postgres> for MiningMode {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&str as Encode<Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}
