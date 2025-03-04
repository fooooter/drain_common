use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};
use openssl::base64;
use openssl::rand::rand_priv_bytes;
use tokio::sync::Mutex;
use crate::cookies::SameSite::Strict;
use crate::cookies::{cookies, SetCookie};

pub trait SessionValue: Send {
    fn as_any(&self) -> &dyn Any;
}

type SessionData = Arc<Mutex<HashMap<String, Box<dyn SessionValue>>>>;

static SESSIONS: LazyLock<Mutex<HashMap<String, SessionData>>> = LazyLock::new(|| {
    Mutex::new(HashMap::new())
});

pub struct Session {
    session_key: String
}

impl Session {
    pub async fn new(session_key: Option<String>, set_cookie: &mut HashMap<String, SetCookie>) -> Self {
        if let Some(session_key) = session_key {
            if SESSIONS.lock().await.contains_key(&session_key) {
                return Self { session_key };
            }
        }

        let mut session_id_bytes: [u8; 16] = [0; 16];
        rand_priv_bytes(&mut session_id_bytes).unwrap();

        let creation_time: [u8; size_of::<u64>()] = SystemTime::now().duration_since(SystemTime::from(UNIX_EPOCH)).unwrap().as_secs().to_be_bytes();

        let mut session_key_bytes: Vec<u8> = Vec::new();
        session_key_bytes.append(&mut creation_time.to_vec());
        session_key_bytes.append(&mut session_id_bytes.to_vec());

        let session_key = base64::encode_block(&*session_key_bytes);

        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_key.to_owned(), Arc::new(Mutex::new(HashMap::new())));

        set_cookie.insert(String::from("SESSION_ID"), SetCookie {
            value: session_key.to_owned(),
            domain: None,
            expires: None,
            httponly: true,
            max_age: None,
            partitioned: false,
            path: None,
            samesite: Some(Strict),
            secure: false
        });

        Self { session_key }
    }

    pub async fn set(&mut self, k: String, v: Box<dyn SessionValue>) -> bool {
        if let Some(session) = SESSIONS.lock().await.get(&self.session_key) {
            session.lock().await.insert(k, v);
            return true;
        }
        false
    }

    pub async fn get<'a, V: SessionValue + Clone + 'static>(&'a self, k: &String) -> Option<V> {
        if let Some(session) = SESSIONS.lock().await.get(&self.session_key) {
            if let Some(session_value) = session.lock().await.get(k) {
                if let Some(session_value_extracted) = session_value.as_any().downcast_ref::<V>() {
                    return Some(session_value_extracted.clone())
                }
            }
        }
        None
    }

    pub fn session_key(&self) -> &String { &self.session_key }

    pub async fn destroy(self) { SESSIONS.lock().await.remove(&self.session_key); }
}

pub async fn start_session(request_headers: &HashMap<String, String>, set_cookie: &mut HashMap<String, SetCookie>) -> Session {
    SESSIONS.lock().await
        .retain(|k, _| {
            let session_key_decoded = &*base64::decode_block(&*k).unwrap();
            let (creation_time, _) = session_key_decoded.split_at(size_of::<u64>());
            if SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - u64::from_be_bytes(creation_time.try_into().unwrap()) > 3600 {
                return false
            }
            true
        });

    if let Some(cookies) = cookies(request_headers) {
        if let Some(session_key) = cookies.get("SESSION_ID") {
            return Session::new(Some(session_key.clone()), set_cookie).await;
        }
    }

    Session::new(None, set_cookie).await
}