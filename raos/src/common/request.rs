#[derive(Clone, Debug)]
pub enum FrontendRequestMethod {
    GET,
    POST,
    OtherUnsupported(String),
}

pub trait FrontendRequest {
    fn request_method(&self) -> FrontendRequestMethod;

    fn header_param(&self, key: &str) -> Option<String>;

    fn query_param(&self, key: &str) -> Option<String>;

    fn body_param(&self, key: &str) -> Option<String>;
}
