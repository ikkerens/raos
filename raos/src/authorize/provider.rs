use async_trait::async_trait;

use crate::common::Grant;

/// Authorization provider trait
/// This is one of the traits that has to be implemented by the end user, for the oauth manager to work.
/// 
/// This trait is used to authorize a grant proven by a authorization code and exchange a code for a grant.
#[async_trait]
pub trait AuthorizationProvider: 'static + Send + Sync {
    /// This is the type of the owner id that is used to identify the resource owner.
    /// This type will need to match the OwnerId used in [TokenProvider](crate::token::TokenProvider).
    type OwnerId;
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
    /// 
    /// # Returns
    /// An [AuthorizationResult] that describes the result of the authorization.
    /// 
    /// # Errors
    /// If the grant is invalid or the authorization provider fails to authorize the grant, through whatever error.
    async fn authorize_grant(&self, grant: &Grant<Self::OwnerId>) -> Result<AuthorizationResult, Self::Error>;

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
    /// 
    /// # Returns
    /// A string that represents the authorization code.
    /// 
    /// # Errors
    /// If the grant is invalid or the authorization provider fails to authorize the grant, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError](crate::common::OAuthError::ProviderImplementationError).
    async fn generate_code_for_grant(&self, grant: Grant<Self::OwnerId>) -> Result<String, Self::Error>;

    /// Exchange an authorization code for a grant.
    /// 
    /// # Implementation notes
    /// This function should return the grant that was previously authorized by [authorize_grant](AuthorizationProvider::generate_code_for_grant).
    /// 
    /// # Arguments
    /// * `code` - The authorization code to exchange for a grant.
    /// 
    /// # Returns
    /// An optional grant that was previously authorized by [authorize_grant](AuthorizationProvider::generate_code_for_grant).
    /// Or None if the code is invalid or expired.
    /// 
    /// # Errors
    /// If the code is invalid or expired, or the authorization provider fails to exchange the code for a grant, through whatever error.
    /// This error will later be returned through [OAuthError::ProviderImplementationError](crate::common::OAuthError::ProviderImplementationError).
    async fn exchange_code_for_grant(
        &self,
        code: String,
    ) -> Result<Option<Grant<Self::OwnerId>>, Self::Error>;
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
