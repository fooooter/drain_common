use std::collections::HashMap;

pub enum SameSite {
    Strict,
    Lax,
    None
}

pub struct SetCookie {
    value: String,
    domain: Option<String>,
    expires: Option<String>,
    httponly: Option<bool>,
    max_age: Option<u32>,
    partitioned: Option<bool>,
    path: Option<String>,
    samesite: Option<SameSite>,
    secure: Option<bool>
}

pub fn cookies(headers: &HashMap<String, String>) -> Option<HashMap<String, String>> {
    let mut cookies: HashMap<String, String> = HashMap::new();

    if let Some(cookies_header) = headers.get("cookie") {
        for cookie in cookies_header.split(';') {
            let cookie_split = cookie.trim().split_once('=').unwrap();
            cookies.insert(String::from(cookie_split.0), String::from(cookie_split.1));
        }
        return Some(cookies);
    }
    None
}