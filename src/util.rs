use std::net::IpAddr;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{Local, NaiveTime, TimeZone};
use pnet::datalink::MacAddr;
use rand::random;

/// Render untrusted server text as one bounded log line. Mark all credential
/// occurrences in the original message before escaping or shortening it, so
/// overlapping credentials and secrets crossing the display limit stay hidden.
pub(crate) fn server_message(message: &str, username: &str, password: &str) -> String {
    const LIMIT: usize = 512;
    const ELLIPSIS: &str = "…";
    let mut hidden = vec![false; message.len()];
    for secret in [username, password] {
        mark_secret(message.as_bytes(), secret.as_bytes(), &mut hidden);
    }
    let mut output = String::with_capacity(LIMIT);
    let mut inside_secret = false;
    for (index, character) in message.char_indices() {
        let display = if hidden[index] {
            if inside_secret {
                continue;
            }
            inside_secret = true;
            "[REDACTED]".to_owned()
        } else {
            inside_secret = false;
            if character.is_control()
                || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                character.escape_default().to_string()
            } else {
                character.to_string()
            }
        };
        if output.len() + display.len() > LIMIT - ELLIPSIS.len() {
            output.push_str(ELLIPSIS);
            break;
        }
        output.push_str(&display);
    }
    output
}

// Prefix matching includes overlapping occurrences in linear time. Each byte
// is marked at most once per secret, even for a long repeated-character value.
fn mark_secret(message: &[u8], secret: &[u8], hidden: &mut [bool]) {
    if secret.is_empty() || secret.len() > message.len() {
        return;
    }
    let mut prefixes = vec![0; secret.len()];
    let mut matched = 0;
    for index in 1..secret.len() {
        while matched > 0 && secret[index] != secret[matched] {
            matched = prefixes[matched - 1];
        }
        if secret[index] == secret[matched] {
            matched += 1;
        }
        prefixes[index] = matched;
    }
    matched = 0;
    let mut covered_until = 0;
    for (index, &byte) in message.iter().enumerate() {
        while matched > 0 && byte != secret[matched] {
            matched = prefixes[matched - 1];
        }
        if byte == secret[matched] {
            matched += 1;
        }
        if matched == secret.len() {
            let end = index + 1;
            hidden[(end - secret.len()).max(covered_until)..end].fill(true);
            covered_until = end;
            matched = prefixes[matched - 1];
        }
    }
}

#[inline]
pub fn ip_to_vec(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

#[inline]
pub fn put_mac(data: &mut BytesMut, mac: &MacAddr) {
    data.put_u8(mac.0);
    data.put_u8(mac.1);
    data.put_u8(mac.2);
    data.put_u8(mac.3);
    data.put_u8(mac.4);
    data.put_u8(mac.5);
}

#[inline]
pub fn get_mac(data: &mut Bytes) -> MacAddr {
    let mut mac = MacAddr::zero();
    mac.0 = data.get_u8();
    mac.1 = data.get_u8();
    mac.2 = data.get_u8();
    mac.3 = data.get_u8();
    mac.4 = data.get_u8();
    mac.5 = data.get_u8();
    mac
}

/// Wait until the next local occurrence of `time` without blocking an executor.
/// A short recheck tolerates wall-clock changes while retries use monotonic time.
pub async fn sleep_at(time: NaiveTime) -> Option<()> {
    let now = Local::now();
    let mut date = now.date_naive();
    let target = loop {
        if let Some(target) = Local.from_local_datetime(&date.and_time(time)).earliest()
            && target > now
        {
            break target;
        }
        date = date.succ_opt()?;
    };
    loop {
        let remaining = target.signed_duration_since(Local::now());
        if remaining <= chrono::Duration::zero() {
            return Some(());
        }
        tokio::time::sleep(remaining.to_std().ok()?.min(Duration::from_secs(30))).await;
    }
}

#[inline]
pub fn random_vec(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(random::<u8>());
    }
    v
}

/// enum of ChannelData.state
///
/// # State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Success,
    Stop,
    Sleep,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelData {
    pub state: State,
    pub data: Vec<u8>,
}

impl ChannelData {
    pub fn stopped() -> Self {
        Self {
            state: State::Stop,
            data: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn server_message_redacts_all_original_overlapping_credentials() {
        for (message, username, password, expected) in [
            (
                "user=alice password=secret again=alice",
                "alice",
                "secret",
                "user=[REDACTED] password=[REDACTED] again=[REDACTED]",
            ),
            ("ababa", "aba", "bab", "[REDACTED]"),
            ("ababa", "aba", "", "[REDACTED]"),
            ("abc", "ab", "bc", "[REDACTED]"),
            ("[alice]", "alice", "REDACTED", "[[REDACTED]]"),
            (
                "欢迎同学，密码=校园密码",
                "同学",
                "校园密码",
                "欢迎[REDACTED]，密码=[REDACTED]",
            ),
            ("normal message", "", "", "normal message"),
        ] {
            assert_eq!(server_message(message, username, password), expected);
        }
    }

    #[test]
    fn server_message_escapes_terminal_commands_and_line_spoofing() {
        let message = "alice\r\n[INFO] forged\t\x1b[2J\x1b]52;c;secret\x07\u{0085}\u{2028}\u{2029}\u{202e}正常";
        let shown = server_message(message, "alice", "secret");
        assert_eq!(
            shown,
            "[REDACTED]\\r\\n[INFO] forged\\t\\u{1b}[2J\\u{1b}]52;c;[REDACTED]\\u{7}\\u{85}\\u{2028}\\u{2029}\\u{202e}正常"
        );
        assert!(!shown.chars().any(char::is_control));
        // Redact first, including control characters that form part of a value.
        assert_eq!(
            server_message("value=p\nass", "", "p\nass"),
            "value=[REDACTED]"
        );
    }

    #[test]
    fn server_message_redacts_before_utf8_safe_display_truncation() {
        let prefix = "中".repeat(164); // 492 bytes, leaving room for one marker.
        let shown = server_message(
            &format!("{prefix}boundary-secret{}", "末".repeat(20)),
            "",
            "boundary-secret",
        );
        assert!(shown.starts_with(&format!("{prefix}[REDACTED]")));
        assert!(!shown.contains("boundary"));
        assert!(shown.ends_with('…'));
        assert!(shown.len() <= 512);
        let shown = server_message(&format!("{}secret", "x".repeat(506)), "", "secret");
        assert_eq!(shown, format!("{}…", "x".repeat(506)));
        // A credential overlapping itself must be hidden beyond a naive
        // non-overlapping replacement's final match, including at high lengths.
        assert_eq!(
            server_message(&"a".repeat(65_535), "", &"a".repeat(4096)),
            "[REDACTED]"
        );
        assert!(server_message(&"\x1b".repeat(1000), "", "").len() <= 512);
    }

    #[test]
    fn ip_octets_preserve_network_order() {
        assert_eq!(
            ip_to_vec(&Ipv4Addr::new(192, 0, 2, 17).into()),
            [192, 0, 2, 17]
        );
        assert_eq!(
            ip_to_vec(&Ipv6Addr::LOCALHOST.into()),
            Ipv6Addr::LOCALHOST.octets()
        );
    }

    #[test]
    fn mac_network_order_round_trip() {
        let mac = MacAddr::new(0x02, 0x11, 0x22, 0xaa, 0xbb, 0xff);
        let mut data = BytesMut::new();
        put_mac(&mut data, &mac);
        assert_eq!(&data[..], &[0x02, 0x11, 0x22, 0xaa, 0xbb, 0xff]);
        assert_eq!(get_mac(&mut data.freeze()), mac);
    }

    #[test]
    fn random_bytes_obey_requested_length() {
        for n in [0, 1, 2, 16, 2048] {
            assert_eq!(random_vec(n).len(), n);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_until_local_time_is_cancellable() {
        let waiting = sleep_at(Local::now().time());
        assert!(
            tokio::time::timeout(Duration::from_millis(1), waiting)
                .await
                .is_err()
        );
    }
}
