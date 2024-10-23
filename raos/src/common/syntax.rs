use crate::common::frontend::OAuthValidationError;
use regex::Regex;
use std::sync::LazyLock;

pub(crate) static CLIENT_ID_SYNTAX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("[ -~]+").unwrap());
pub(crate) static STATE_SYNTAX: LazyLock<Regex> = LazyLock::new(|| Regex::new("[!-~]+").unwrap());

pub(crate) trait ValidateSyntax {
    fn validate_syntax(&self, key: &'static str, regex: &Regex)
        -> Result<(), OAuthValidationError>;
}

impl ValidateSyntax for String {
    fn validate_syntax(
        &self,
        key: &'static str,
        regex: &Regex,
    ) -> Result<(), OAuthValidationError> {
        if !regex.is_match(self) {
            return Err(OAuthValidationError::InvalidParameterSyntax(key, regex.to_string()));
        }

        Ok(())
    }
}

impl ValidateSyntax for Option<String> {
    fn validate_syntax(
        &self,
        key: &'static str,
        regex: &Regex,
    ) -> Result<(), OAuthValidationError> {
        if let Some(value) = self {
            value.validate_syntax(key, regex)?;
        }

        Ok(())
    }
}
