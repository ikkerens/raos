use crate::common::{CodeChallenge, FrontendRequest, FrontendRequestMethod, OAuthValidationError};

#[derive(Debug)]
pub enum ResponseType {
    Code,
}

pub struct AuthorizationRequest {
    pub response_type: ResponseType,
    pub client_id: String,
    pub code_challenge: CodeChallenge,
    pub has_openid_nonce: bool,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
}

impl TryFrom<&dyn FrontendRequest> for AuthorizationRequest {
    type Error = OAuthValidationError;

    fn try_from(request: &dyn FrontendRequest) -> Result<Self, Self::Error> {
        if !matches!(
            request.request_method(),
            FrontendRequestMethod::GET | FrontendRequestMethod::POST
        ) {
            return Err(OAuthValidationError::InvalidRequestMethod {
                expected: FrontendRequestMethod::GET,
                actual: request.request_method(),
            });
        }

        // Helper function to get a parameter from either the query or body if it's a POST request
        let param = |key| {
            request.query_param(key).or_else(|| {
                if let FrontendRequestMethod::POST = request.request_method() {
                    request.body_param(key)
                } else {
                    None
                }
            })
        };

        // Get the response type, client ID, and code challenge method from the request
        let response_type = match param("response_type") {
            Some(str) => str.try_into()?,
            None => return Err(OAuthValidationError::MissingRequiredParameter("response_type")),
        };
        let Some(client_id) = param("client_id") else {
            return Err(OAuthValidationError::MissingRequiredParameter("client_id"));
        };
        let code_challenge =
            (param("code_challenge"), param("code_challenge_method")).try_into()?;

        // Return the authorization request
        Ok(Self {
            response_type,
            client_id,
            code_challenge,
            has_openid_nonce: param("nonce").is_some(),
            redirect_uri: param("redirect_uri"),
            scope: param("scope"),
            state: param("state"),
        })
    }
}

impl TryFrom<String> for ResponseType {
    type Error = OAuthValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Match the response type string to an enum variant
        Ok(match value.to_lowercase().as_str() {
            "code" => Self::Code,
            _ => {
                return Err(OAuthValidationError::InvalidParameterValue(
                    "response_type",
                    value.to_string(),
                ))
            }
        })
    }
}

impl TryFrom<(Option<String>, Option<String>)> for CodeChallenge {
    type Error = OAuthValidationError;

    fn try_from(
        (code_challenge, code_challenge_method): (Option<String>, Option<String>),
    ) -> Result<Self, Self::Error> {
        let Some(code_challenge) = code_challenge else {
            return Ok(Self::None);
        };
        let Some(method) = code_challenge_method else {
            return Ok(Self::Plain { code_challenge });
        };

        // Match the code challenge method string to an enum variant
        Ok(match method.to_lowercase().as_str() {
            "plain" => Self::Plain { code_challenge },
            "s256" => Self::S256 { code_challenge },
            _ => {
                return Err(OAuthValidationError::InvalidParameterValue(
                    "code_challenge_method",
                    method,
                ))
            }
        })
    }
}
