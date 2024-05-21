use axum::{http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use ethers::utils::to_checksum;
use jsonwebtoken::{EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Deserialize)]
pub struct Signature {
    message: String,
    signature: String,
    timestamp: i64,
}

#[derive(Serialize)]
pub struct AuthToken {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JWTClaims {
    aud: String,
    exp: i64,
    iat: i64,
    iss: String,
    sub: String,
}

pub enum AuthenticateUserError {
    InvalidSignature,
    TokenGenerationFail,
}

pub async fn authenticate_user(
    Json(signature): Json<Signature>,
) -> Result<Json<AuthToken>, AuthenticateUserError> {
    if !is_valid_sig_timestamp(&signature) {
        return Err(AuthenticateUserError::InvalidSignature);
    }

    let authenticated_address =
        get_signature_owner(&signature).map_err(|_| AuthenticateUserError::InvalidSignature)?;

    let token = get_auth_token(&authenticated_address)
        .map_err(|_| AuthenticateUserError::TokenGenerationFail)?;

    Ok(Json(AuthToken { token }))
}

fn get_validity_window(timestamp: i64) -> (i64, i64) {
    (timestamp, timestamp + (60 * 1000))
}

fn is_valid_sig_timestamp(sig: &Signature) -> bool {
    let now = Utc::now().timestamp_millis();
    let (validity_start, validity_end) = get_validity_window(sig.timestamp);
    now >= validity_start && now <= validity_end
}

fn get_signature_owner(sig: &Signature) -> Result<String, ()> {
    let signature = ethers::core::types::Signature::from_str(&sig.signature).map_err(|_| ())?;
    let message = format!("{} [{}]", sig.message, sig.timestamp);
    let recovered = signature.recover(message.as_str()).map_err(|_| ())?;
    let recovered = to_checksum(&recovered, None);
    Ok(recovered)
}

fn get_auth_token(authenticated_address: &str) -> Result<String, ()> {
    let now = Utc::now().timestamp_millis();
    let claims = JWTClaims {
        iss: "DailyTookayServer".to_owned(),
        aud: "DailyTookayClient".to_owned(),
        iat: now,
        exp: now + (3600 * 1000),
        sub: authenticated_address.to_owned(),
    };

    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("secret".as_ref()),
    )
    .map_err(|_| ())
}

impl IntoResponse for AuthenticateUserError {
    fn into_response(self) -> axum::response::Response {
        // How we want errors responses to be serialized
        #[derive(Serialize)]
        struct ErrorResponse {
            message: String,
        }

        let (status, message) = match self {
            Self::InvalidSignature => (StatusCode::UNAUTHORIZED, "Invalid signature"),
            Self::TokenGenerationFail => (StatusCode::UNAUTHORIZED, "Token creation failed"),
        };

        (
            status,
            axum::Json(ErrorResponse {
                message: message.to_owned(),
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{is_valid_sig_timestamp, Signature};
    use crate::routes::authenticate::get_signature_owner;
    use chrono::Utc;
    use ethers::utils::to_checksum;

    fn get_sig_timestamp(t: i64) -> Signature {
        Signature {
            message: "Hello there, Name's Venom".to_owned(),
            signature: "".to_owned(),
            timestamp: t,
        }
    }

    #[test]
    fn check_signature_expiry_past_timestamp() {
        // minus a millis time greater than the window which is 60 sec
        let past_time = Utc::now().timestamp_millis() - (70 * 1000); // 10 sec ahead of window
        assert_eq!(is_valid_sig_timestamp(&get_sig_timestamp(past_time)), false);
    }

    #[test]
    fn check_signature_expiry_valid_time() {
        let exact_window_start_time = Utc::now().timestamp_millis(); // exactly at the begining of the window
        let middle_window_time = Utc::now().timestamp_millis() - (30 * 1000); // somewhere in the middle
        let exact_window_end_time = Utc::now().timestamp_millis() - (60 * 1000); // exactly at the end of the window

        assert_eq!(
            is_valid_sig_timestamp(&get_sig_timestamp(exact_window_start_time)),
            true
        );
        assert_eq!(
            is_valid_sig_timestamp(&get_sig_timestamp(middle_window_time)),
            true
        );
        assert_eq!(
            is_valid_sig_timestamp(&get_sig_timestamp(exact_window_end_time)),
            true
        );
    }

    #[test]
    fn check_signature_expiry_future_timestamp() {
        let past_time = Utc::now().timestamp_millis() + (10 * 1000); // 10 sec in the future
        assert_eq!(is_valid_sig_timestamp(&get_sig_timestamp(past_time)), false);
    }

    #[tokio::test]
    async fn check_signature_owner_valid_owner() -> anyhow::Result<()> {
        use ethers::core::k256::ecdsa::SigningKey;
        use ethers::signers::{Signer, Wallet};

        let pv_key = "a39b71de864611362729eb3e05974a93a96179724e4751c9e4dd7b8099bd7d42";
        let message: &str = "Hello there, Name's Venom";
        let wallet: Wallet<SigningKey> = pv_key.parse().unwrap();

        let signature = wallet
            .sign_message(&format!("{} [{}]", message, 10)[..])
            .await?;

        let sig = Signature {
            message: message.to_owned(),
            signature: signature.to_string(),
            timestamp: 10,
        };

        let owner = get_signature_owner(&sig).unwrap();
        assert_eq!(
            owner,
            to_checksum(
                &"0x52471a768b76B8cC647f2F28198cB0E44C38C2cF"
                    .parse()
                    .unwrap(),
                None
            )
        );

        Ok(())
    }
}
