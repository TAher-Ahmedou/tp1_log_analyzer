use crate::parser::FailedLogin;
use std::collections::HashMap;

pub fn count_by_ip(events: &[FailedLogin]) -> Vec<(String, usize)> {
    let mut map: HashMap<String, usize> = HashMap::new();
    for event in events {
        *map.entry(event.ip.clone()).or_insert(0) += 1;
    }
    let mut result: Vec<(String, usize)> = map.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

pub fn count_by_user(events: &[FailedLogin]) -> Vec<(String, usize)> {
    let mut map: HashMap<String, usize> = HashMap::new();
    for event in events {
        *map.entry(event.user.clone()).or_insert(0) += 1;
    }
    let mut result: Vec<(String, usize)> = map.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(user: &str, ip: &str) -> FailedLogin {
        FailedLogin {
            user: user.to_string(),
            ip: ip.to_string(),
        }
    }

    #[test]
    fn test_count_by_ip_sorted() {
        let events = vec![
            make_event("root", "1.1.1.1"),
            make_event("admin", "1.1.1.1"),
            make_event("test", "2.2.2.2"),
        ];
        let result = count_by_ip(&events);
        assert_eq!(result[0], ("1.1.1.1".to_string(), 2));
        assert_eq!(result[1], ("2.2.2.2".to_string(), 1));
    }

    #[test]
    fn test_count_by_user_sorted() {
        let events = vec![
            make_event("root", "1.1.1.1"),
            make_event("root", "2.2.2.2"),
            make_event("admin", "3.3.3.3"),
        ];
        let result = count_by_user(&events);
        assert_eq!(result[0], ("root".to_string(), 2));
        assert_eq!(result[1], ("admin".to_string(), 1));
    }
}
