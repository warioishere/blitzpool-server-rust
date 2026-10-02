// SPDX-License-Identifier: AGPL-3.0-or-later

//! The two JWTs the adapters mint, signed with `ring`: RS256 for the FCM
//! service-account grant, ES256 for VAPID. A JWT is `header.claims.signature`,
//! each part base64url without padding.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, RSA_PKCS1_SHA256,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::PrivateKeyDer;
use serde::Serialize;

/// A signing key with its JWT algorithm.
pub(crate) enum JwtKey {
    Rs256(RsaKeyPair),
    Es256(EcdsaKeyPair),
}

impl JwtKey {
    /// An RSA key as PEM, PKCS#8 (`BEGIN PRIVATE KEY`, what Google issues) or
    /// PKCS#1 (`BEGIN RSA PRIVATE KEY`).
    pub(crate) fn rs256_from_pem(pem: &str) -> Result<Self, String> {
        let der = PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| e.to_string())?;
        let pair = match &der {
            PrivateKeyDer::Pkcs8(k) => RsaKeyPair::from_pkcs8(k.secret_pkcs8_der()),
            PrivateKeyDer::Pkcs1(k) => RsaKeyPair::from_der(k.secret_pkcs1_der()),
            _ => return Err("not an RSA private key".to_string()),
        };
        pair.map(Self::Rs256).map_err(|e| e.to_string())
    }

    /// A P-256 key as PKCS#8 DER.
    pub(crate) fn es256_from_pkcs8(der: &[u8]) -> Result<Self, String> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &SystemRandom::new())
            .map(Self::Es256)
            .map_err(|e| e.to_string())
    }

    fn alg(&self) -> &'static str {
        match self {
            Self::Rs256(_) => "RS256",
            Self::Es256(_) => "ES256",
        }
    }

    /// `claims` as a signed compact JWT.
    pub(crate) fn sign(&self, claims: &impl Serialize) -> Result<String, String> {
        #[derive(Serialize)]
        struct Header {
            typ: &'static str,
            alg: &'static str,
        }
        let header = b64_json(&Header {
            typ: "JWT",
            alg: self.alg(),
        })?;
        let message = format!("{header}.{}", b64_json(claims)?);
        let rng = SystemRandom::new();
        let signature = match self {
            Self::Rs256(pair) => {
                let mut sig = vec![0u8; pair.public().modulus_len()];
                pair.sign(&RSA_PKCS1_SHA256, &rng, message.as_bytes(), &mut sig)
                    .map_err(|e| e.to_string())?;
                sig
            }
            // The FIXED encoding is r||s, the form JWS requires for ES256.
            Self::Es256(pair) => pair
                .sign(&rng, message.as_bytes())
                .map_err(|e| e.to_string())?
                .as_ref()
                .to_vec(),
        };
        Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }
}

fn b64_json(value: &impl Serialize) -> Result<String, String> {
    let json = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{
        KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256,
    };

    /// Generated for these tests only; it signs nothing real.
    const TEST_ONLY_RSA_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrLHvo/yIAC1Hp
iueNk39atLCrcdDxJuO56RIhAUv2Xa5KWrOcrnIQ4VvKUQ3oWmxfmbIo7mRd9hA8
BflyIQgMAzwaOPf1V2C3pRUJuM75p1CDCWYi6a7Nay1bOgm7YdxBaEVgzwIZh2/M
8d/lp13/+56raGW0wBuX8CrYKsOS3fpolgfRa8AwLEZJu139fwc7I4D2CwD34t+C
Mh6J2nkXKUXjDtDvubjqrdhU2cIskY8hiLmrkx6KZCPN7MwCGfppIXBnplYH/Q0p
IscF+28ZbiMbBV4Oipce6HdUU1lawNpVfTAWl0r5hHksiPtsNZamaXab8h2Uybdc
MpA6El5DAgMBAAECggEAEptCxYMaMIlfzYmY/ZriCzuR6rOeroqiKBQYMY3rsmuL
ewScpTQ8gkOPj+Xl+PL/TcMDX+SjSf1p1VnMPCYwCDzqcb/t4CAv4LZ+m3Bt0IBp
8DHQ2uGuQSEHLJ/vQoxIKLSguf22hjeNJRNzrt8rCMd9VLeD5V/D1W0N/d0O0O4c
/C4fBt6gm/qOSYBWOa+Ils8unto03PrnOmJ6yDzOF/Xb9O0fyxQ1fx0mP9/J21Qa
t6f/Z55LTXfVA29tRTI4h9WvbQOQ5Iw1RMfB0DDAVhifsLltpA6FgKSjllI12vHd
mMSrXdwGiQVW97tQK8ZG90U1U7cWzrEJSJQgv536IQKBgQDRedTT3Hc9PrFps9Mu
RUhWf1OJ2kek8Fel1XE+HD+Z8X62BMiMtDSaPVHYpqWCSrgkJhHsPJzwqG5lolEo
u3xsdlV5rlm55JlppTeMIb/bgCeZP2NrOksxUa8GFYDzjzQU6Hn0WXqfrFV8zPYB
ussUcoa+19rpth2i72oQHF7WYwKBgQDRMOiUwAEaCwrRCUMbinbTYyYzlkYwCx8x
8DQJ4+DTm7RsXxngx3QdEQKEi8IjrjL30SLUnET4msKtysHj1HXCb7/ZnV8bsaYp
jlC6IsIvTTmb/KpNbfZ52pZerI8PTFwHZiOsJouVHxtB7im0iBeDLub6jJvh5wC+
xicKoiVuoQKBgB+qbhzUwAW3G3SiJXNiL8w7lTJKl/f8CRPdjy/Xb1njIsd7M6Hp
f+YtDNlWX8CxcOKuCpmOlB7hJ0cf4Wrp5KY0wTkSvSeXwgUxX5NEas9QsSu+ZFYK
SuGaun2N9J9c73+VoRHqENpgX8/s3+dlCFv/8BSbZtFboWFHFd53m3KHAoGAJ7LF
YH0zeFLCIbtFPfO/6wu00zNgbHuf1uVDquDQ6LdyvOIrUgnn0iBJPwgatpS3XWoV
1w001YzhBwQkWW0XT+fPG6gOxX2oD9jPHxO7kChyl1SSqREGJkfCI4NRvtB54nmS
qXfDI3B8xr1Ast7kv2NmOAP5DRy+enW2MQFmYyECgYEAnBMu65gdRmJGlE2dr+tE
2rFgkQV9dL/U1Lcjazre/vnRSkUd38htJYmoTT22TBsDdDt9gY7un8syXwqC0Wz0
HxQWn/jLxRcY01loHHYskWvAeJ3QH8NaswGd0JN/claY6TT9Yn+0ypzZ1S5QKSG/
Li7ebo/5WDb9M8znJWJAbbY=
-----END PRIVATE KEY-----";
    /// The same test-only key in PKCS#1 form.
    const TEST_ONLY_RSA_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqyx76P8iAAtR6YrnjZN/WrSwq3HQ8SbjuekSIQFL9l2uSlqz
nK5yEOFbylEN6FpsX5myKO5kXfYQPAX5ciEIDAM8Gjj39Vdgt6UVCbjO+adQgwlm
IumuzWstWzoJu2HcQWhFYM8CGYdvzPHf5add//ueq2hltMAbl/Aq2CrDkt36aJYH
0WvAMCxGSbtd/X8HOyOA9gsA9+LfgjIeidp5FylF4w7Q77m46q3YVNnCLJGPIYi5
q5MeimQjzezMAhn6aSFwZ6ZWB/0NKSLHBftvGW4jGwVeDoqXHuh3VFNZWsDaVX0w
FpdK+YR5LIj7bDWWpml2m/IdlMm3XDKQOhJeQwIDAQABAoIBABKbQsWDGjCJX82J
mP2a4gs7keqznq6KoigUGDGN67Jri3sEnKU0PIJDj4/l5fjy/03DA1/ko0n9adVZ
zDwmMAg86nG/7eAgL+C2fptwbdCAafAx0NrhrkEhByyf70KMSCi0oLn9toY3jSUT
c67fKwjHfVS3g+Vfw9VtDf3dDtDuHPwuHwbeoJv6jkmAVjmviJbPLp7aNNz65zpi
esg8zhf12/TtH8sUNX8dJj/fydtUGren/2eeS0131QNvbUUyOIfVr20DkOSMNUTH
wdAwwFYYn7C5baQOhYCko5ZSNdrx3ZjEq13cBokFVve7UCvGRvdFNVO3Fs6xCUiU
IL+d+iECgYEA0XnU09x3PT6xabPTLkVIVn9TidpHpPBXpdVxPhw/mfF+tgTIjLQ0
mj1R2Kalgkq4JCYR7Dyc8KhuZaJRKLt8bHZVea5ZueSZaaU3jCG/24AnmT9jazpL
MVGvBhWA8480FOh59Fl6n6xVfMz2AbrLFHKGvtfa6bYdou9qEBxe1mMCgYEA0TDo
lMABGgsK0QlDG4p202MmM5ZGMAsfMfA0CePg05u0bF8Z4Md0HREChIvCI64y99Ei
1JxE+JrCrcrB49R1wm+/2Z1fG7GmKY5QuiLCL005m/yqTW32edqWXqyPD0xcB2Yj
rCaLlR8bQe4ptIgXgy7m+oyb4ecAvsYnCqIlbqECgYAfqm4c1MAFtxt0oiVzYi/M
O5UySpf3/AkT3Y8v129Z4yLHezOh6X/mLQzZVl/AsXDirgqZjpQe4SdHH+Fq6eSm
NME5Er0nl8IFMV+TRGrPULErvmRWCkrhmrp9jfSfXO9/laER6hDaYF/P7N/nZQhb
//AUm2bRW6FhRxXed5tyhwKBgCeyxWB9M3hSwiG7RT3zv+sLtNMzYGx7n9blQ6rg
0Oi3crziK1IJ59IgST8IGraUt11qFdcNNNWM4QcEJFltF0/nzxuoDsV9qA/Yzx8T
u5AocpdUkqkRBiZHwiODUb7QeeJ5kql3wyNwfMa9QLLe5L9jZjgD+Q0cvnp1tjEB
ZmMhAoGBAJwTLuuYHUZiRpRNna/rRNqxYJEFfXS/1NS3I2s63v750UpFHd/IbSWJ
qE09tkwbA3Q7fYGO7p/LMl8KgtFs9B8UFp/4y8UXGNNZaBx2LJFrwHid0B/DWrMB
ndCTf3JWmOk0/WJ/tMqc2dUuUCkhvy4u3m6P+Vg2/TPM5yViQG22
-----END RSA PRIVATE KEY-----";

    #[derive(Serialize)]
    struct Claims {
        aud: &'static str,
        exp: u64,
    }
    const CLAIMS: Claims = Claims {
        aud: "https://example.invalid",
        exp: 1_900_000_000,
    };

    fn split(jwt: &str) -> (serde_json::Value, serde_json::Value, String, Vec<u8>) {
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "{jwt}");
        let json = |p: &str| -> serde_json::Value {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
        };
        (
            json(parts[0]),
            json(parts[1]),
            format!("{}.{}", parts[0], parts[1]),
            URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
    }

    /// Both PEM forms load, and the signature verifies under the public key.
    #[test]
    fn an_rs256_jwt_verifies_under_its_public_key() {
        for pem in [TEST_ONLY_RSA_PKCS8, TEST_ONLY_RSA_PKCS1] {
            let key = JwtKey::rs256_from_pem(pem).expect("rsa key");
            let JwtKey::Rs256(pair) = &key else {
                panic!("rs256 key");
            };
            let public = pair.public_key().as_ref().to_vec();
            let (header, claims, message, sig) = split(&key.sign(&CLAIMS).unwrap());
            assert_eq!(header["alg"], "RS256");
            assert_eq!(header["typ"], "JWT");
            assert_eq!(claims["aud"], CLAIMS.aud);
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
                .verify(message.as_bytes(), &sig)
                .expect("signature verifies");
        }
    }

    /// ES256 signatures are the 64-byte r||s form JWS requires.
    #[test]
    fn an_es256_jwt_verifies_under_its_public_key() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = JwtKey::es256_from_pkcs8(pkcs8.as_ref()).expect("ec key");
        let JwtKey::Es256(pair) = &key else {
            panic!("es256 key");
        };
        let public = pair.public_key().as_ref().to_vec();
        let (header, _, message, sig) = split(&key.sign(&CLAIMS).unwrap());
        assert_eq!(header["alg"], "ES256");
        assert_eq!(sig.len(), 64);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public)
            .verify(message.as_bytes(), &sig)
            .expect("signature verifies");
    }

    #[test]
    fn a_non_rsa_pem_is_refused() {
        assert!(JwtKey::rs256_from_pem("not a pem").is_err());
    }
}
