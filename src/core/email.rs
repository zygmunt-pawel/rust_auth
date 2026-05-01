#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

#[derive(Debug, PartialEq, Eq)]
pub struct EmailError;

impl TryFrom<String> for Email {
    type Error = EmailError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let normalized = value.to_lowercase();
        if normalized.len() < 3 || normalized.len() > 254 { return Err(EmailError); }
        if !normalized.contains('@') { return Err(EmailError); }
        if normalized.contains('\r') || normalized.contains('\n') { return Err(EmailError); }
        Ok(Email(normalized))
    }
}

impl Email {
    pub fn as_str(&self) -> &str { &self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_email() {
        let e = Email::try_from("User@Example.COM".to_string()).unwrap();
        assert_eq!(e.as_str(), "user@example.com");
    }

    #[test] fn rejects_too_short() { assert!(Email::try_from("a@".to_string()).is_err()); }
    #[test] fn rejects_too_long() {
        let local = "a".repeat(250);
        assert!(Email::try_from(format!("{local}@b.co")).is_err());
    }
    #[test] fn rejects_missing_at() { assert!(Email::try_from("nope".to_string()).is_err()); }
    #[test] fn rejects_cr_lf() {
        assert!(Email::try_from("u@e.co\n".to_string()).is_err());
        assert!(Email::try_from("u@\re.co".to_string()).is_err());
    }
    #[test] fn accepts_valid() { assert!(Email::try_from("u@e.co".to_string()).is_ok()); }
}
