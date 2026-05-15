#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedLogin {
    pub user: String,
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    Failed(FailedLogin),
    Ignored,
    Malformed,
}

pub fn parse_line(line: &str) -> ParseOutcome {
    // Ignore accepted logins
    if line.contains("Accepted password") {
        return ParseOutcome::Ignored;
    }

    // Handle "Invalid user X from IP" (no "Failed password" prefix)
    if line.contains("Invalid user") && line.contains("from") && !line.contains("Failed password") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let user = parts
            .iter()
            .position(|&w| w == "user")
            .and_then(|i| parts.get(i + 1));
        let ip = parts
            .iter()
            .position(|&w| w == "from")
            .and_then(|i| parts.get(i + 1));
        return match (user, ip) {
            (Some(u), Some(i)) => ParseOutcome::Failed(FailedLogin {
                user: u.to_string(),
                ip: i.to_string(),
            }),
            _ => ParseOutcome::Malformed,
        };
    }

    // Handle "Failed password for [invalid user] X from IP"
    if line.contains("Failed password for") && line.contains("from") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let for_pos = parts.iter().position(|&w| w == "for");
        let from_pos = parts.iter().position(|&w| w == "from");

        if let (Some(fp), Some(fromp)) = (for_pos, from_pos) {
            let user =
                if parts.get(fp + 1) == Some(&"invalid") && parts.get(fp + 2) == Some(&"user") {
                    parts.get(fp + 3)
                } else {
                    parts.get(fp + 1)
                };
            let ip = parts.get(fromp + 1);

            return match (user, ip) {
                (Some(u), Some(i)) => ParseOutcome::Failed(FailedLogin {
                    user: u.to_string(),
                    ip: i.to_string(),
                }),
                _ => ParseOutcome::Malformed,
            };
        }
        return ParseOutcome::Malformed;
    }

    ParseOutcome::Malformed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failed_normal_user() {
        let line = "Jan 10 08:16:03 srv01 sshd[1002]: Failed password for root from 198.51.100.23 port 55432 ssh2";
        assert_eq!(
            parse_line(line),
            ParseOutcome::Failed(FailedLogin {
                user: "root".to_string(),
                ip: "198.51.100.23".to_string(),
            })
        );
    }

    #[test]
    fn test_failed_invalid_user() {
        let line = "Jan 10 08:15:21 srv01 sshd[1001]: Failed password for invalid user admin from 203.0.113.10 port 34567 ssh2";
        assert_eq!(
            parse_line(line),
            ParseOutcome::Failed(FailedLogin {
                user: "admin".to_string(),
                ip: "203.0.113.10".to_string(),
            })
        );
    }

    #[test]
    fn test_accepted_login_ignored() {
        let line = "Jan 10 08:16:44 srv01 sshd[1003]: Accepted password for student from 192.0.2.15 port 44822 ssh2";
        assert_eq!(parse_line(line), ParseOutcome::Ignored);
    }

    #[test]
    fn test_malformed_line_no_crash() {
        let line = "MALFORMED LINE WITHOUT EXPECTED SSH FIELDS";
        assert_eq!(parse_line(line), ParseOutcome::Malformed);
    }

    #[test]
    fn test_invalid_user_without_password() {
        let line =
            "Jan 10 08:19:41 srv01 sshd[1006]: Invalid user oracle from 192.0.2.55 port 51200";
        assert_eq!(
            parse_line(line),
            ParseOutcome::Failed(FailedLogin {
                user: "oracle".to_string(),
                ip: "192.0.2.55".to_string(),
            })
        );
    }
}
