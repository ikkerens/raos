/// The FrontendRequestMethod enum describes the two supported request methods.
/// For other methods, the OtherUnsupported variant is used.
#[derive(Clone, Debug, PartialEq)]
pub enum FrontendRequestMethod {
    /// HTTP GET
    GET,
    /// HTTP POST
    POST,
    /// Other request methods, e.g. PUT, DELETE, etc., used for logging and error purposes.
    OtherUnsupported(String),
}

/// Frontend request wrapper to be implemented by server framework wrappers
/// to provide a unified interface for handling requests.
pub trait FrontendRequest {
    /// Returns the request method.
    fn request_method(&self) -> FrontendRequestMethod;

    /// Returns value of the specified header parameter.
    fn header_param(&self, key: &str) -> Option<String>;

    /// Returns value of the specified query parameter.
    fn query_param(&self, key: &str) -> Option<String>;

    /// Returns value of the specified body parameter, likely from application/x-www-form-urlencoded encoding.
    fn body_param(&self, key: &str) -> Option<String>;
}
