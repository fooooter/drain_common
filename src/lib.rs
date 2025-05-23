pub mod cookies;
pub mod sessions;

use std::collections::HashMap;

pub enum RequestData<'a> {
    Get(&'a Option<HashMap<String, String>>),
    Post {params: &'a Option<HashMap<String, String>>, data: &'a Option<RequestBody>},
    Head(&'a Option<HashMap<String, String>>),
    Put {params: &'a Option<HashMap<String, String>>, data: &'a Option<RequestBody>},
    Delete {params: &'a Option<HashMap<String, String>>, data: &'a Option<RequestBody>},
    Patch {params: &'a Option<HashMap<String, String>>, data: &'a Option<RequestBody>}
}

pub struct FormDataValue {
    pub filename: Option<String>,
    pub headers: HashMap<String, String>,
    pub value: Vec<u8>
}

pub enum RequestBody {
    XWWWFormUrlEncoded(HashMap<String, String>),
    FormData(HashMap<String, FormDataValue>),
    Plain(String),
    OctetStream(Vec<u8>)
}