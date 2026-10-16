//! `tearmesh hook`: a Claude Code hook (SessionStart, UserPromptSubmit, PostToolUse). It tells the
//! session about letters that arrived since it was last told, once each. It never fails the turn.

use serde_json::{Value, json};
use tokio::io::AsyncReadExt;

use crate::ipc::{Client, Request};
use crate::node::Letter;

pub async fn run() -> anyhow::Result<()> {
    let mut input = String::new();
    let _ = tokio::io::stdin().read_to_string(&mut input).await;
    let event = serde_json::from_str::<Value>(&input)
        .ok()
        .and_then(|v| v["hook_event_name"].as_str().map(String::from))
        .unwrap_or_else(|| "UserPromptSubmit".into());
    // No daemon, or this user isn't in a boundary: stay quiet.
    let Ok((mut client, address)) = Client::session(false).await else {
        return Ok(());
    };
    let Ok(v) = client.call(&Request::Notify).await else {
        return Ok(());
    };
    let letters: Vec<Letter> = serde_json::from_value(v).unwrap_or_default();
    if let Some(out) = render(&event, &address, &letters) {
        println!("{out}");
    }
    Ok(())
}

pub fn render(event: &str, address: &str, letters: &[Letter]) -> Option<String> {
    if letters.is_empty() {
        return None;
    }
    let mut text = format!(
        "📨 tear-mesh: {} new letter(s) for {address}:\n",
        letters.len()
    );
    for l in letters {
        text.push_str(&format!(
            "- {} from {}: {}\n",
            &l.id[..12],
            l.from,
            l.subject
        ));
    }
    text.push_str(
        "Open one with the tearmesh `read` tool; reply with `post` and `thread` set to its id.",
    );
    Some(
        json!({ "hookSpecificOutput": { "hookEventName": event, "additionalContext": text } })
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_once_per_batch() {
        assert!(render("UserPromptSubmit", "a@b", &[]).is_none());
        let l = Letter {
            id: "ab".repeat(32),
            from: "builder@ws".into(),
            to: vec!["a@b".into()],
            subject: "hi".into(),
            thread: None,
            ts: 0,
            read: false,
            body: None,
        };
        let out: Value =
            serde_json::from_str(&render("PostToolUse", "a@b", &[l]).unwrap()).unwrap();
        assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        assert!(
            out["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap()
                .contains("abababababab from builder@ws: hi")
        );
    }
}
