use crate::common::{
    frontend::{FrontendRequest, FrontendRequestMethod, OAuthValidationError},
    model::CodeChallenge,
    syntax::{ValidateSyntax, CLIENT_ID_SYNTAX, STATE_SYNTAX},
    util::NoneIfEmpty,
};

/// The response type expected in an authorization request.
#[derive(Debug, PartialEq)]
pub enum ResponseType {
    /// The client is requesting an authorization code.
    Code,
}

/// A parsed authorization request from a client.
/// This struct contains all the information needed to authorize a client's request.
/// This is produced by parsing a [FrontendRequest] from a client.
#[derive(Debug)]
pub struct AuthorizationRequest {
    /// The response type expected in the request.
    pub response_type: ResponseType,
    /// The client ID of the client making the request.
    pub client_id: String,
    /// The code challenge and method used in the request.
    pub code_challenge: CodeChallenge,
    /// The redirect URI the client expects to be redirected to.
    pub redirect_uri: Option<String>,
    /// The scope of the request, space separated
    pub scope: Option<String>,
    /// The state of the request to be sent back to the client in the response.
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
            request.query_param(key).none_if_empty().or_else(|| {
                if let FrontendRequestMethod::POST = request.request_method() {
                    request.body_param(key).none_if_empty()
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
        client_id.validate_syntax("client_id", &CLIENT_ID_SYNTAX)?;
        let code_challenge =
            (param("code_challenge"), param("code_challenge_method")).try_into()?;

        let state = param("state");
        state.validate_syntax("state", &STATE_SYNTAX)?;

        // Return the authorization request
        Ok(Self {
            response_type,
            client_id,
            code_challenge,
            state,
            redirect_uri: param("redirect_uri"),
            scope: param("scope"),
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
