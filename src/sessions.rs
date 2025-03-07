use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use openssl::base64;
use openssl::rand::rand_priv_bytes;
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::Instant;
use crate::cookies::SameSite::Strict;
use crate::cookies::{cookies, SetCookie};

pub trait SessionValue: Send {
    fn as_any(&self) -> &dyn Any;
}

struct SessionData {
    creation_time: Instant,
    session_contents: Arc<Mutex<HashMap<String, Box<dyn SessionValue>>>>,
}

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

        let mut session_key_bytes: [u8; 16] = [0; 16];
        rand_priv_bytes(&mut session_key_bytes).unwrap();

        let session_key = base64::encode_block(&session_key_bytes);

        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_key.to_owned(), SessionData {
            creation_time: Instant::now(),
            session_contents: Arc::new(Mutex::new(HashMap::new()))
        });

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
            session.session_contents.lock().await.insert(k, v);
            return true;
        }
        false
    }

    pub async fn get<'a, V: SessionValue + Clone + 'static>(&'a self, k: &String) -> Option<V> {
        if let Some(session) = SESSIONS.lock().await.get(&self.session_key) {
            if let Some(session_value) = session.session_contents.lock().await.get(k) {
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
    task::spawn(async move {
        SESSIONS.lock().await
            .retain(|_, v| {
                if Instant::now().duration_since(v.creation_time).as_secs() > 3600 {
                    return false
                }
                true
            });
    });

    if let Some(cookies) = cookies(request_headers) {
        if let Some(session_key) = cookies.get("SESSION_ID") {
            return Session::new(Some(session_key.clone()), set_cookie).await;
        }
    }

    Session::new(None, set_cookie).await
}