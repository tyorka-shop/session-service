use lazy_static::lazy_static;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::str;
use std::sync::Mutex;
use time::ext::NumericalDuration;
use time::OffsetDateTime;

pub struct CacheEntry {
    value: String,
    expiring: i64,
}

lazy_static! {
    static ref CACHE: Mutex<HashMap<String, CacheEntry>> = Mutex::new(HashMap::new());
}

pub fn get<T: DeserializeOwned + Clone>(key: &str) -> Option<T> {
    let cache = CACHE.lock().unwrap();
    match cache.get(key.into()) {
        Some(ref entry) => {
            if entry.expiring > OffsetDateTime::now_utc().unix_timestamp() {
                let result = serde_json::from_str::<T>(&entry.value.clone()).unwrap();
                return Some(result);
            }
            None
        }
        None => None,
    }
}

pub fn insert<T: Serialize>(key: &str, value: &T, ttl: i64) {
    let mut cache = CACHE.lock().unwrap();

    let expiring = OffsetDateTime::now_utc()
        .checked_add(ttl.seconds())
        .unwrap()
        .unix_timestamp();

    cache.insert(
        String::from(key),
        CacheEntry {
            expiring,
            value: serde_json::to_string(value).unwrap(),
        },
    );
}

#[cfg(test)]
mod test_cache {
    use serde::{Deserialize, Serialize};

    const KEY: &str = "key";
    const VALUE: &str = "value";

    #[test]
    fn ok() {
        super::insert(KEY, &VALUE, 10);

        assert_eq!(super::get::<String>(KEY).unwrap(), VALUE);
    }

    #[test]
    fn expiring() {
        super::insert(KEY, &VALUE, -1);

        assert_eq!(super::get::<String>(KEY), None);
    }

    #[test]
    fn payload() {
        #[derive(Serialize, Deserialize, Debug, Clone)]
        struct Value {
            pub name: String,
        }

        let value = Value { name: VALUE.into() };

        super::insert(KEY, &value, 10);

        assert_eq!(super::get::<Value>(KEY).unwrap().name, VALUE);
    }
}
