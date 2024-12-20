pub mod cookies;

use std::collections::HashMap;

pub enum RequestData<'a> {
    Get(&'a Option<HashMap<String, String>>),
    Post(&'a Option<HashMap<String, String>>),
    Head
}