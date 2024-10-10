use base64::{prelude::BASE64_STANDARD, Engine};

use crate::common::{FrontendRequest, FrontendRequestMethod, OAuthValidationError};

/// A parsed request to exchange an authorization code, refresh code or client credentials for an access token.
pub struct TokenRequest {
    /// The client ID.
    pub client_id: String,
    /// The client secret.
    pub client_secret: Option<String>,
    /// The type of grant requested by the client.
    pub grant_type: RequestedGrantType,
    /// The requested scope, used when refreshing a token using the refresh token grant type.
    pub scope: Option<Vec<String>>,
}

/// The type of grant requested by the client.
pub enum RequestedGrantType {
    /// The client is requesting an access token using client credentials.
    ClientCredentials,
    /// The client is requesting an access token using an authorization code.
    AuthorizationCode {
        /// The authorization code.
        code: String,
        /// The code verifier used to answer the PKCE challenge.
        code_verifier: String,
    },
    /// The client is requesting an access token using a refresh token.
    RefreshToken {
        /// The refresh token.
        refresh_token: String,
    },
}

impl TryFrom<&dyn FrontendRequest> for TokenRequest {
    type Error = OAuthValidationError;

    fn try_from(request: &dyn FrontendRequest) -> Result<Self, Self::Error> {
        if !matches!(request.request_method(), FrontendRequestMethod::POST) {
            return Err(OAuthValidationError::InvalidRequestMethod {
                expected: FrontendRequestMethod::POST,
                actual: request.request_method(),
            });
        }

        let header_credentials = get_credentials_from_header(request)?;

        let (mut client_id, mut client_secret) = header_credentials.unzip();
        if let Some(body_client_id) = request.body_param("client_id") {
            if let Some(header_client_id) = client_id {
                if body_client_id != header_client_id {
                    return Err(OAuthValidationError::MismatchedClientCredentials);
                }
            }

            client_id = Some(body_client_id);
        };
        if let Some(body_client_secret) = request.body_param("client_secret") {
            if client_secret.is_none() {
                client_secret = Some(body_client_secret);
            }
        };

        let Some(client_id) = client_id else {
            return Err(OAuthValidationError::MissingRequiredParameter("client_id"));
        };

        let Some(grant_type_str) = request.body_param("grant_type") else {
            return Err(OAuthValidationError::MissingRequiredParameter("grant_type"));
        };

        let grant_type = match grant_type_str.as_str() {
            "client_credentials" => RequestedGrantType::ClientCredentials,
            "authorization_code" => {
                let code = match request.body_param("code") {
                    Some(code) => code,
                    None => return Err(OAuthValidationError::MissingRequiredParameter("code")),
                };
                let code_verifier = match request.body_param("code_verifier") {
                    Some(code_verifier) => code_verifier,
                    None => {
                        return Err(OAuthValidationError::MissingRequiredParameter("code_verifier"))
                    }
                };
                RequestedGrantType::AuthorizationCode { code, code_verifier }
            }
            "refresh_token" => {
                let refresh_token = match request.body_param("refresh_token") {
                    Some(refresh_token) => refresh_token,
                    None => {
                        return Err(OAuthValidationError::MissingRequiredParameter("refresh_token"))
                    }
                };
                RequestedGrantType::RefreshToken { refresh_token }
            }
            _ => {
                return Err(OAuthValidationError::InvalidParameterValue(
                    "grant_type",
                    grant_type_str,
                ))
            }
        };

        let scope = request.body_param("scope").map(|s| s.split(" ").map(str::to_string).collect());

        Ok(TokenRequest { client_id, client_secret, grant_type, scope })
    }
}

fn get_credentials_from_header(
    request: &dyn FrontendRequest,
) -> Result<Option<(String, String)>, OAuthValidationError> {
    static MASKED: &str = "<masked>";

    if let Some(authorization_header) = request.header_param("authorization") {
        // Parse the authorization header
        let parts: Vec<&str> = authorization_header.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(OAuthValidationError::InvalidParameterValue(
                "authorization",
                MASKED.to_string(),
            ));
        }
        if parts[0].to_lowercase() != "Basic" {
            return Err(OAuthValidationError::InvalidParameterValue(
                "authorization",
                MASKED.to_string(),
            ));
        }
        let decoded = BASE64_STANDARD.decode(parts[1]).map_err(|_| {
            OAuthValidationError::InvalidParameterValue("authorization", MASKED.to_string())
        })?;
        let decoded_str = std::str::from_utf8(&decoded).map_err(|_| {
            OAuthValidationError::InvalidParameterValue("authorization", MASKED.to_string())
        })?;
        let parts: Vec<&str> = decoded_str.split(':').collect();
        if parts.len() != 2 {
            return Err(OAuthValidationError::InvalidParameterValue(
                "authorization",
                MASKED.to_string(),
            ));
        }
        return Ok(Some((parts[0].to_string(), parts[1].to_string())));
    }

    Ok(None)
}
