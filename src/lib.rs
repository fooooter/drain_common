pub mod cookies;

use std::collections::HashMap;

pub enum RequestData<'a> {
    Get(&'a Option<HashMap<String, String>>),
    Post(&'a Option<RequestBody>),
    Head
}

pub struct FormDataValue {
    pub filename: Option<String>,
    pub value: Vec<u8>
}

pub enum RequestBody {
    XWWWFormUrlEncoded(HashMap<String, String>),
    FormData(HashMap<String, FormDataValue>)
}