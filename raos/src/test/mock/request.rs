use crate::common::{FrontendRequest, FrontendRequestMethod};
use std::collections::HashMap;

/// A mocked frontend request for testing purposes.
/// This struct implements the [FrontendRequest] trait and can be used to test the OAuthManager.
pub struct RequestFromRawHttp {
    /// The parsed request method of the request.
    pub method: FrontendRequestMethod,
    /// The parsed query parameters of the request.
    pub query: HashMap<String, String>,
    /// The parsed headers of the request.
    pub headers: HashMap<String, String>,
    /// The parsed body parameters of the request.
    pub body: HashMap<String, String>,
}

impl FrontendRequest for RequestFromRawHttp {
    fn request_method(&self) -> FrontendRequestMethod {
        self.method.clone()
    }

    fn header_param(&self, key: &str) -> Option<String> {
        self.headers.get(key).cloned()
    }

    fn query_param(&self, key: &str) -> Option<String> {
        self.query.get(key).cloned()
    }

    fn body_param(&self, key: &str) -> Option<String> {
        self.body.get(key).cloned()
    }
}

/// Create a mocked frontend request for testing purposes.
/// This function will create a new [RequestFromRawHttp] with the given parameters.
///
/// # Parameters
/// - `request` - The raw request string to parse into a [RequestFromRawHttp]
///
/// # Returns
/// A [RequestFromRawHttp] that can be used to test the OAuthManager.
///
/// # Example
/// See [test_request_from_raw_http] for an example of how to use this function.
pub fn request_from_raw_http(request: &str) -> RequestFromRawHttp {
    let mut request = request.trim().split('\n');

    // Read the first line which contains method and path
    let mut first_line = request.next().unwrap().trim().split(' ');
    let method = match first_line.next().unwrap() {
        "GET" => FrontendRequestMethod::GET,
        "POST" => FrontendRequestMethod::POST,
        s => FrontendRequestMethod::OtherUnsupported(s.to_string()),
    };
    let query = match first_line.next().unwrap().split_once('?') {
        Some((_, query)) => serde_urlencoded::from_str(query).unwrap(),
        None => HashMap::new(),
    };

    let mut headers = HashMap::new();
    for mut line in request.by_ref() {
        line = line.trim();

        // We've reached the body
        if line.is_empty() {
            break;
        }

        let (key, value) = line.split_once(':').unwrap();
        headers.insert(key.trim().to_string(), value.trim().to_string());
    }

    let body = request.map(|s| s.trim().to_string()).collect::<Vec<String>>().join("\n");
    let body = serde_urlencoded::from_str(&body).unwrap();

    RequestFromRawHttp { method, query, headers, body }
}

#[test]
fn test_request_from_raw_http() {
    let request = request_from_raw_http(
        r#"
         GET /authorize?client_id=1234&response_type=code HTTP/1.1
         Host: localhost:8080
         Content-Type: application/x-www-form-urlencoded
         
         code_challenge=5678&code_challenge_method=S256
     "#,
    );

    assert_eq!(request.request_method(), FrontendRequestMethod::GET);
    assert_eq!(request.query_param("client_id"), Some("1234".to_string()));
    assert_eq!(request.query_param("response_type"), Some("code".to_string()));
    assert_eq!(request.header_param("Host"), Some("localhost:8080".to_string()));
    assert_eq!(
        request.header_param("Content-Type"),
        Some("application/x-www-form-urlencoded".to_string())
    );
    assert_eq!(request.body_param("code_challenge"), Some("5678".to_string()));
    assert_eq!(request.body_param("code_challenge_method"), Some("S256".to_string()));
}
