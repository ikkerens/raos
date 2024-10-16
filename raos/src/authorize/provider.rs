use async_trait::async_trait;

use crate::common::{FrontendResponse, FrontendResponseExt, Grant, OAuthError};

/// Authorization provider trait
/// This is one of the traits that has to be implemented by the end user, for the oauth manager to work.
///
/// This trait is used to authorize a grant proven by a authorization code and exchange a code for a grant.
#[async_trait]
pub trait AuthorizationProvider: 'static + Send + Sync {
    /// This is the type of the owner id that is used to identify the resource owner.
    /// This type will need to match the OwnerId used in [TokenProvider](crate::token::TokenProvider).
    type OwnerId;
    /// This is the type of the extras that can be passed down from the top-level authorization functions.
    /// This can contain things like request information to [authorize_grant](AuthorizationProvider::authorize_grant).
    type Extras;
    /// This is the error type that can be returned by the authorization provider implementing this trait.
    /// This type will need to match the Error used in [TokenProvider](crate::token::TokenProvider) and [ClientProvider](crate::common::ClientProvider).
    type Error;

    /// Authorize a grant.
    ///
    /// # Implementation notes
    /// This function should return an [AuthorizationResult] that describes the result of the authorization.
    /// If the result is [AuthorizationResult::Authorized], the authorization flow will continue and a code will be generated and returned.
    /// If the result is [AuthorizationResult::RequireAuthentication], the client should be prompted to ask the resource owner to authenticate.
    /// If the result is [AuthorizationResult::RequireScopeConsent], the client should be prompted to ask the resource owner for consent.
    /// If the result is [AuthorizationResult::Unauthorized], the authorization flow will be stopped and an error will be returned to the client.
    ///
    /// # Arguments
    /// * `grant` - The grant to authorize.
    /// * `extras` - An optional parameter that can be passed down from the top-level authorize function, this can contain things like request information. This is useful to add context like session info to the authorization provider.
    ///
    /// # Returns
    /// An [AuthorizationResult] that describes the result of the authorization.
    ///
    /// # Errors
    /// If the grant is invalid or the authorization provider fails to authorize the grant, through whatever error.
    async fn authorize_grant(
        &self,
        grant: &Grant<Self::OwnerId>,
        extras: &mut Option<Self::Extras>,
    ) -> Result<AuthorizationResult, Self::Error>;

    /// Generate an authorization code for a grant.
    ///
    /// # Implementation notes
    /// This function should return a fully random authorization code that can later be reversed
    /// to a grant through [exchange_code_for_grant](AuthorizationProvider::exchange_code_for_grant)
    /// which is part of this same trait.
    /// You should not use any readable or predictable values for the authorization code, such as JWT.
    ///
    /// # Arguments
    /// * `grant` - The grant to authorize.
    /// * `extras` - An optional parameter that can be passed down from the top-level functions. This can contain things like request information.
    ///
    /// # Returns
    /// A string that represents the authorization code.
    ///
    /// # Errors
    /// If the grant is invalid or the authorization provider fails to authorize the grant, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError].
    async fn generate_code_for_grant(
        &self,
        grant: Grant<Self::OwnerId>,
    ) -> Result<String, Self::Error>;

    /// Exchange an authorization code for a grant.
    ///
    /// # Implementation notes
    /// This function should return the grant that was previously authorized by [authorize_grant](AuthorizationProvider::generate_code_for_grant).
    ///
    /// # Arguments
    /// * `code` - The authorization code to exchange for a grant.
    /// * `extras` - An optional parameter that can be passed down from the top-level functions. This can contain things like request information.
    ///
    /// # Returns
    /// An optional grant that was previously authorized by [authorize_grant](AuthorizationProvider::generate_code_for_grant).
    /// Or None if the code is invalid or expired.
    ///
    /// # Errors
    /// If the code is invalid or expired, or the authorization provider fails to exchange the code for a grant, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError].
    async fn exchange_code_for_grant(
        &self,
        code: String,
    ) -> Result<Option<Grant<Self::OwnerId>>, Self::Error>;

    /// Handle a required authentication.
    /// This function should return a response that can be sent to the client to prompt the resource owner to authenticate.
    /// This is used when the resource owner needs to authenticate before the grant can be authorized.
    ///
    /// # Arguments
    /// * `extras` - An optional parameter that can be passed down from the top-level functions. This can contain things like request information.
    ///
    /// # Returns
    /// A [FrontendResponse] that can be used to build a response to the client.
    ///
    /// # Errors
    /// If the authorization provider fails to handle the required authentication, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError].
    ///
    /// # Default implementation
    /// The default implementation of this function will return an [OAuthError::AccessDenied] error.
    async fn handle_required_authentication(
        &self,
        _extras: &mut Option<Self::Extras>,
    ) -> Result<FrontendResponse, Self::Error> {
        Ok(OAuthError::<()>::AccessDenied.into_frontend_response())
    }

    /// Handle a required scope consent.
    /// This function should return a response that can be sent to the client to prompt the resource owner to consent to the requested scopes.
    /// This is used when the resource owner needs to consent to the requested scopes before the grant can be authorized.
    ///
    /// # Arguments
    /// * `scopes` - The scopes that the resource owner needs to consent to.
    /// * `extras` - An optional parameter that can be passed down from the top-level functions. This can contain things like request information.
    ///
    /// # Returns
    /// A [FrontendResponse] that can be used to build a response to the client.
    ///
    /// # Errors
    /// If the authorization provider fails to handle the required scope consent, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError].
    ///
    /// # Default implementation
    /// The default implementation of this function will return an [OAuthError::AccessDenied] error.
    async fn handle_missing_scope_consent(
        &self,
        _scopes: Vec<String>,
        _extras: &mut Option<Self::Extras>,
    ) -> Result<FrontendResponse, Self::Error> {
        Ok(OAuthError::<()>::AccessDenied.into_frontend_response())
    }
}

/// The result of an authorization request.
pub enum AuthorizationResult {
    /// The grant was authorized, the flow will continue to return an authorization code.
    Authorized,
    /// The resource owner needs to authenticate before the grant can be authorized.
    RequireAuthentication,
    /// The resource owner needs to consent to the requested scopes before the grant can be authorized.
    RequireScopeConsent(Vec<String>),
    /// The grant was unauthorized, the flow will stop and return an error to the client.
    Unauthorized,
}
