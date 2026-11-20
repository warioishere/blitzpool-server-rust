// SPDX-License-Identifier: AGPL-3.0-or-later

//! Postgres `sqlx` impls for the primitive types, here rather than in `bp-db`
//! because of the orphan rule, and [`crate::impl_pg_text_enum`] for the text-backed
//! enums other crates define.

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

// ----- Text-backed enums <-> VARCHAR -----

/// `sqlx::Type`, `Decode` and `Encode` for an enum stored as its text form:
/// `as_str()` writes it, `FromStr` reads it, and an unknown value fails the
/// row decode instead of turning into some default. The using crate needs
/// `sqlx` as a dependency.
#[macro_export]
macro_rules! impl_pg_text_enum {
    ($t:ty) => {
        impl ::sqlx::Type<::sqlx::Postgres> for $t {
            fn type_info() -> ::sqlx::postgres::PgTypeInfo {
                <::std::string::String as ::sqlx::Type<::sqlx::Postgres>>::type_info()
            }
            fn compatible(ty: &::sqlx::postgres::PgTypeInfo) -> bool {
                <::std::string::String as ::sqlx::Type<::sqlx::Postgres>>::compatible(ty)
            }
        }

        impl<'r> ::sqlx::Decode<'r, ::sqlx::Postgres> for $t {
            fn decode(
                value: ::sqlx::postgres::PgValueRef<'r>,
            ) -> ::std::result::Result<Self, ::sqlx::error::BoxDynError> {
                let s = <&str as ::sqlx::Decode<::sqlx::Postgres>>::decode(value)?;
                <$t as ::std::str::FromStr>::from_str(s).map_err(|e| e.to_string().into())
            }
        }

        impl<'q> ::sqlx::Encode<'q, ::sqlx::Postgres> for $t {
            fn encode_by_ref(
                &self,
                buf: &mut ::sqlx::postgres::PgArgumentBuffer,
            ) -> ::std::result::Result<::sqlx::encode::IsNull, ::sqlx::error::BoxDynError> {
                <&str as ::sqlx::Encode<::sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
            }
        }
    };
}

impl_pg_text_enum!(MiningMode);
