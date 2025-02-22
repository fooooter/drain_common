use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use openssl::base64;
use openssl::rand::rand_priv_bytes;
use tokio::sync::{Mutex, OwnedMutexGuard};
use crate::cookies::SameSite::Strict;
use crate::cookies::{cookies, SetCookie};

pub trait SessionValue: Send {
    fn as_any(&self) -> &dyn Any;
}

static SESSIONS: LazyLock<Arc<Mutex<HashMap<String, Arc<Mutex<HashMap<String, Box<dyn SessionValue>>>>>>>> = LazyLock::new(|| {
    Arc::new(Mutex::new(HashMap::new()))
});

pub struct Session {
    session_key: String,
    session_data: Arc<Mutex<HashMap<String, Box<dyn SessionValue>>>>,
    sessions_ref: OwnedMutexGuard<HashMap<String, Arc<Mutex<HashMap<String, Box<dyn SessionValue>>>>>>
}

impl Session {
    pub async fn new(session_key: Option<String>, set_cookie: &mut HashMap<String, SetCookie>) -> Self {
        let mut sessions = SESSIONS.clone().lock_owned().await;

        if let Some(session_key) = session_key {
            if let Some(session_data) = sessions.get(&session_key) {
                return Self { session_key, session_data: session_data.clone(), sessions_ref: sessions };
            }
        }

        let mut session_id_bytes: [u8; 16] = [0; 16];
        rand_priv_bytes(&mut session_id_bytes).unwrap();

        let session_key = base64::encode_block(&session_id_bytes);

        sessions.insert(session_key.to_owned(), Arc::new(Mutex::new(HashMap::new())));

        let session_data = sessions.get(&session_key).unwrap().clone();

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

        Self { session_key, session_data, sessions_ref: sessions }
    }

    pub async fn set(&mut self, k: String, v: Box<dyn SessionValue>) {
        self.session_data.lock().await.insert(k, v);
    }

    pub async fn get<'a, V: SessionValue + Clone + 'static>(&'a self, k: &'a String) -> Option<V> {
        if let Some(session_value) = self.session_data.lock().await.get(k) {
            if let Some(session_value_extracted) = session_value.as_any().downcast_ref::<V>() {
                return Some(session_value_extracted.clone())
            }
        }
        None
    }

    pub fn session_key(&self) -> &String {
        &self.session_key
    }

    pub async fn destroy(mut self) {
        self.sessions_ref.remove(&self.session_key);
    }
}

pub async fn start_session(request_headers: &HashMap<String, String>, set_cookie: &mut HashMap<String, SetCookie>) -> Session {
    if let Some(cookies) = cookies(request_headers) {
        if let Some(session_key) = cookies.get("SESSION_ID") {
            return Session::new(Some(session_key.clone()), set_cookie).await;
        }
    }

    Session::new(None, set_cookie).await
}