use std::collections::HashMap;

pub enum SameSite {
    Strict,
    Lax,
    None
}

pub struct SetCookie {
    pub value: String,
    pub domain: Option<String>,
    pub expires: Option<String>,
    pub httponly: bool,
    pub max_age: Option<u32>,
    pub partitioned: bool,
    pub path: Option<String>,
    pub samesite: Option<SameSite>,
    pub secure: bool
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