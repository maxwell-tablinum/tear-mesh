//! One SQLite file per boundary. `entries` is append-only (triggers refuse UPDATE and DELETE);
//! `seen` is this machine's own read/notified state, `screen` its screening verdicts and `idem`
//! the keys of recent posts; none is ever synced.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use iroh::EndpointId;
use rusqlite::{Connection, OptionalExtension, params};

use crate::envelope::{Entry, Envelope};

pub struct Store {
    conn: Connection,
    max_bytes: u64,
}

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS entries (
  id TEXT PRIMARY KEY,
  author TEXT NOT NULL,
  seq INTEGER NOT NULL,
  thread TEXT,
  from_addr TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'info',
  envelope TEXT NOT NULL,
  sig TEXT NOT NULL,
  body TEXT NOT NULL,
  UNIQUE (author, seq)
);
CREATE TABLE IF NOT EXISTS rcpt (id TEXT NOT NULL, addr TEXT NOT NULL, PRIMARY KEY (id, addr));
CREATE INDEX IF NOT EXISTS rcpt_addr ON rcpt (addr);
CREATE INDEX IF NOT EXISTS entries_thread ON entries (thread);
CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries
  BEGIN SELECT RAISE(ABORT, 'entries are append-only'); END;
CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries
  BEGIN SELECT RAISE(ABORT, 'entries are append-only'); END;
CREATE TABLE IF NOT EXISTS seen (
  mailbox TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, PRIMARY KEY (mailbox, id, kind)
);
CREATE TABLE IF NOT EXISTS screen (
  id TEXT PRIMARY KEY, verdict TEXT NOT NULL, reason TEXT NOT NULL, ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS idem (
  mailbox TEXT NOT NULL, key TEXT NOT NULL, id TEXT NOT NULL, ts INTEGER NOT NULL, what TEXT NOT NULL,
  PRIMARY KEY (mailbox, key)
);
CREATE INDEX IF NOT EXISTS entries_kind_from ON entries (kind, from_addr);
";

/// A stored letter, as returned to readers.
#[derive(Clone, Debug)]
pub struct Stored {
    pub id: String,
    pub env: Envelope,
    pub body: String,
}

#[derive(Clone, Copy)]
pub enum Seen {
    Read,
    Notified,
}

impl Seen {
    fn as_str(self) -> &'static str {
        match self {
            Seen::Read => "read",
            Seen::Notified => "notified",
        }
    }
}

impl Store {
    pub fn open(path: &Path, max_bytes: u64) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.execute_batch(SCHEMA)?;
        // 0.1.0 logs predate `kind`; every entry in them is a letter.
        let has_kind: bool = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name = 'kind'",
            [],
            |r| r.get(0),
        )?;
        if !has_kind {
            conn.execute_batch("ALTER TABLE entries ADD COLUMN kind TEXT NOT NULL DEFAULT 'info'")?;
        }
        Ok(Store { conn, max_bytes })
    }

    /// Highest seq held per author.
    pub fn heads(&self) -> Result<BTreeMap<String, u64>> {
        let mut st = self
            .conn
            .prepare("SELECT author, MAX(seq) FROM entries GROUP BY author")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// (seq, id) of the author's latest entry.
    pub fn head(&self, author: &EndpointId) -> Result<Option<(u64, String)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT seq, id FROM entries WHERE author = ?1 ORDER BY seq DESC LIMIT 1",
                [author.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Appends an entry that policy already accepted. Returns false if it was already held.
    /// Each author's chain must stay contiguous: seq = head + 1 and prev = head's id.
    pub fn insert(&mut self, entry: &Entry, env: &Envelope) -> Result<bool> {
        let id = entry.id();
        let tx = self.conn.transaction()?;
        let size: u64 = tx.query_row(
            "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
            [],
            |r| r.get(0),
        )?;
        ensure!(size < self.max_bytes, "boundary log is full ({size} bytes)");
        if tx
            .query_row("SELECT 1 FROM entries WHERE id = ?1", [&id], |_| Ok(()))
            .optional()?
            .is_some()
        {
            return Ok(false);
        }
        let head: Option<(u64, String)> = tx
            .query_row(
                "SELECT seq, id FROM entries WHERE author = ?1 ORDER BY seq DESC LIMIT 1",
                [env.author.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match &head {
            Some((seq, _)) if env.seq <= *seq => {
                bail!(
                    "fork: {} already has seq {} with a different entry",
                    env.author.fmt_short(),
                    env.seq
                )
            }
            Some((seq, hid)) => {
                ensure!(env.seq == seq + 1, "gap: have seq {seq}, got {}", env.seq);
                ensure!(
                    env.prev.as_deref() == Some(hid.as_str()),
                    "prev doesn't match the chain"
                );
            }
            None => ensure!(
                env.seq == 1,
                "gap: first entry from this author has seq {}",
                env.seq
            ),
        }
        tx.execute(
            "INSERT INTO entries (id, author, seq, thread, from_addr, kind, envelope, sig, body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id,
                env.author.to_string(),
                env.seq,
                env.thread,
                env.from,
                env.kind.as_str(),
                entry.envelope,
                entry.sig,
                entry.body
            ],
        )?;
        for a in &env.to {
            tx.execute(
                "INSERT OR IGNORE INTO rcpt (id, addr) VALUES (?1, ?2)",
                params![id, a],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// The author's entries after `after_seq`, oldest first.
    pub fn since(&self, author: &str, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
        let mut st = self.conn.prepare(
            "SELECT envelope, sig, body FROM entries WHERE author = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = st.query_map(params![author, after_seq, limit as i64], |r| {
            Ok(Entry {
                envelope: r.get(0)?,
                sig: r.get(1)?,
                body: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Looks up by full id or a unique prefix of at least 6 hex chars.
    pub fn get(&self, id: &str) -> Result<Option<Stored>> {
        ensure!(
            id.len() >= 6 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "ids are 6+ hex chars"
        );
        let mut st = self
            .conn
            .prepare("SELECT id, envelope, body FROM entries WHERE id LIKE ?1 || '%' LIMIT 2")?;
        let rows: Vec<Stored> = st
            .query_map([id.to_ascii_lowercase()], row_stored)?
            .collect::<rusqlite::Result<_>>()?;
        ensure!(rows.len() < 2, "id prefix {id} is ambiguous");
        Ok(rows.into_iter().next())
    }

    /// Letters in the thread rooted at `root`, the root included.
    pub fn thread_len(&self, root: &str) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE id = ?1 OR thread = ?1",
            [root],
            |r| r.get(0),
        )?)
    }

    /// Letters addressed to `addr` (or to everyone), not sent by it, oldest first, with the
    /// mailbox's seen flag of `kind`.
    pub fn mail_for(&self, mailbox: &str, addr: &str, kind: Seen) -> Result<Vec<(Stored, bool)>> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT e.id, e.envelope, e.body,
                    EXISTS (SELECT 1 FROM seen s WHERE s.mailbox = ?1 AND s.id = e.id AND s.kind = ?3)
             FROM entries e JOIN rcpt r ON r.id = e.id
             WHERE r.addr IN (?2, '*') AND e.from_addr != ?2
               AND e.kind IN ('info', 'task', 'question', 'claim')
             ORDER BY e.rowid",
        )?;
        let rows = st.query_map(params![mailbox, addr, kind.as_str()], |r| {
            Ok((row_stored(r)?, r.get::<_, bool>(3)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn mark(&self, mailbox: &str, id: &str, kind: Seen) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO seen (mailbox, id, kind) VALUES (?1, ?2, ?3)",
            params![mailbox, id, kind.as_str()],
        )?;
        Ok(())
    }

    /// Marks where screening starts, once: after everything this log already holds. Those
    /// letters were readable before, so they are neither hidden nor sent to the model.
    pub fn screen_start(&self) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO screen (id, verdict, reason, ts)
             SELECT 'start', 'start', '', COALESCE(MAX(rowid), 0) FROM entries",
            [],
        )?;
        Ok(())
    }

    /// Whether the screener cleared the letter, a person released it, or it predates screening.
    pub fn screened_ok(&self, id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM entries e WHERE e.id = ?1 AND (
                   e.rowid <= (SELECT ts FROM screen WHERE id = 'start')
                   OR EXISTS (SELECT 1 FROM screen s WHERE s.id = e.id AND s.verdict IN ('clean', 'released')))",
                [id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Records the screener's verdict; false if the letter already has one.
    pub fn set_verdict(&self, id: &str, verdict: &str, reason: &str, ts: u64) -> Result<bool> {
        Ok(self.conn.execute(
            "INSERT OR IGNORE INTO screen (id, verdict, reason, ts) VALUES (?1, ?2, ?3, ?4)",
            params![id, verdict, reason, ts],
        )? == 1)
    }

    /// Flagged -> released; false if the letter isn't flagged.
    pub fn release(&self, id: &str, ts: u64) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE screen SET verdict = 'released', ts = ?2 WHERE id = ?1 AND verdict = 'flagged'",
            params![id, ts],
        )? == 1)
    }

    /// Letters to `machine` (or everyone) with no verdict yet, written by another author than
    /// `me` or by a guest, oldest first.
    pub fn unscreened(&self, me: &str, machine: &str) -> Result<Vec<Stored>> {
        let mut st = self.conn.prepare(
            "SELECT e.id, e.envelope, e.body FROM entries e
             WHERE e.kind IN ('info', 'task', 'question', 'claim')
               AND (e.author != ?1 OR json_extract(e.envelope, '$.label.trust') = 'guest')
               AND NOT EXISTS (SELECT 1 FROM screen s WHERE s.id = e.id)
               AND e.rowid > COALESCE((SELECT ts FROM screen WHERE id = 'start'), 0)
               AND EXISTS (SELECT 1 FROM rcpt r WHERE r.id = e.id
                           AND (r.addr = '*' OR substr(r.addr, -length(?2) - 1) = '@' || ?2))
             ORDER BY e.rowid",
        )?;
        let rows = st.query_map(params![me, machine], row_stored)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Flagged letters with the reason and when, oldest first.
    pub fn flagged(&self) -> Result<Vec<(Stored, String, u64)>> {
        let mut st = self.conn.prepare(
            "SELECT e.id, e.envelope, e.body, s.reason, s.ts FROM entries e JOIN screen s ON s.id = e.id
             WHERE s.verdict = 'flagged' ORDER BY s.ts",
        )?;
        let rows = st.query_map([], |r| Ok((row_stored(r)?, r.get(3)?, r.get(4)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Every address that has sent mail in this boundary.
    pub fn senders(&self) -> Result<Vec<String>> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT from_addr FROM entries WHERE kind IN ('info', 'task', 'question', 'claim')
             ORDER BY from_addr",
        )?;
        let rows = st.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Entries of one kind (offers or bios), oldest first.
    pub fn of_kind(&self, kind: crate::envelope::Kind) -> Result<Vec<Stored>> {
        let mut st = self
            .conn
            .prepare("SELECT id, envelope, body FROM entries WHERE kind = ?1 ORDER BY rowid")?;
        let rows = st.query_map([kind.as_str()], row_stored)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The newest record of `kind` from each sender address.
    pub fn newest_per_sender(&self, kind: crate::envelope::Kind) -> Result<Vec<Stored>> {
        let mut st = self.conn.prepare(
            "SELECT id, envelope, body FROM entries WHERE rowid IN
             (SELECT MAX(rowid) FROM entries WHERE kind = ?1 GROUP BY from_addr) ORDER BY rowid",
        )?;
        let rows = st.query_map([kind.as_str()], row_stored)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Letters sent from `addr`, oldest first.
    pub fn sent_by(&self, addr: &str) -> Result<Vec<Stored>> {
        let mut st = self.conn.prepare(
            "SELECT id, envelope, body FROM entries
             WHERE from_addr = ?1 AND kind IN ('info', 'task', 'question', 'claim') ORDER BY rowid",
        )?;
        let rows = st.query_map([addr], row_stored)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The letter `mailbox` posted with `key` at or after `since` (unix ms), and the hash of what
    /// was asked. Older keys are forgotten first.
    pub fn idem(&self, mailbox: &str, key: &str, since: u64) -> Result<Option<(String, String)>> {
        self.conn.execute("DELETE FROM idem WHERE ts < ?1", [since])?;
        Ok(self
            .conn
            .query_row(
                "SELECT id, what FROM idem WHERE mailbox = ?1 AND key = ?2",
                [mailbox, key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    pub fn set_idem(&self, mailbox: &str, key: &str, id: &str, ts: u64, what: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO idem (mailbox, key, id, ts, what) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![mailbox, key, id, ts, what],
        )?;
        Ok(())
    }

    pub fn count(&self) -> Result<u64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))?)
    }
}

fn row_stored(r: &rusqlite::Row) -> rusqlite::Result<Stored> {
    let envelope: String = r.get(1)?;
    let env = serde_json::from_str(&envelope).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(Stored {
        id: r.get(0)?,
        env,
        body: r.get(2)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::envelope;
    use iroh::SecretKey;

    #[test]
    fn screening_starts_after_what_the_log_already_held() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("work.db"), 1 << 30).unwrap();
        let k = SecretKey::generate();
        let e1 = Entry::sign(&envelope(&k, 1, None, "a"), "a".into(), &k).unwrap();
        assert!(s.insert(&e1, &e1.open().unwrap()).unwrap());
        assert!(!s.screened_ok(&e1.id()).unwrap(), "no start mark: nothing is exempt");
        s.screen_start().unwrap();
        let e2 = Entry::sign(&envelope(&k, 2, Some(e1.id()), "b"), "b".into(), &k).unwrap();
        assert!(s.insert(&e2, &e2.open().unwrap()).unwrap());
        s.screen_start().unwrap();
        assert!(s.screened_ok(&e1.id()).unwrap() && !s.screened_ok(&e2.id()).unwrap(), "the mark is set once");
        assert!(s.flagged().unwrap().is_empty());
        assert!(s.set_verdict(&e2.id(), "clean", "", 1).unwrap());
        assert!(s.screened_ok(&e2.id()).unwrap());
    }

    #[test]
    fn chain_rules_and_append_only() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("work.db"), 1 << 30).unwrap();
        let k = SecretKey::generate();
        let e1 = Entry::sign(&envelope(&k, 1, None, "a"), "a".into(), &k).unwrap();
        let env1 = e1.open().unwrap();
        assert!(s.insert(&e1, &env1).unwrap());
        assert!(!s.insert(&e1, &env1).unwrap(), "duplicate is a no-op");

        // seq 3 before seq 2 is a gap.
        let e3 = Entry::sign(&envelope(&k, 3, Some(e1.id()), "c"), "c".into(), &k).unwrap();
        assert!(s.insert(&e3, &e3.open().unwrap()).is_err());

        // seq 2 must point at seq 1.
        let wrong =
            Entry::sign(&envelope(&k, 2, Some("00".repeat(32)), "b"), "b".into(), &k).unwrap();
        assert!(s.insert(&wrong, &wrong.open().unwrap()).is_err());
        let e2 = Entry::sign(&envelope(&k, 2, Some(e1.id()), "b"), "b".into(), &k).unwrap();
        assert!(s.insert(&e2, &e2.open().unwrap()).unwrap());

        // A second, different seq 1 is a fork.
        let fork = Entry::sign(&envelope(&k, 1, None, "x"), "x".into(), &k).unwrap();
        assert!(s.insert(&fork, &fork.open().unwrap()).is_err());

        assert_eq!(s.heads().unwrap()[&k.public().to_string()], 2);
        assert_eq!(
            s.since(&k.public().to_string(), 1, 10).unwrap(),
            vec![e2.clone()]
        );
        assert_eq!(s.get(&e2.id()[..8]).unwrap().unwrap().body, "b");

        assert!(s.conn.execute("DELETE FROM entries", []).is_err());
        assert!(s.conn.execute("UPDATE entries SET body = 'z'", []).is_err());

        let mail = s.mail_for("admin", "admin@laptop", Seen::Read).unwrap();
        assert_eq!(mail.len(), 2);
        s.mark("admin", &e1.id(), Seen::Read).unwrap();
        let mail = s.mail_for("admin", "admin@laptop", Seen::Read).unwrap();
        assert!(mail[0].1 && !mail[1].1);
    }

    #[test]
    fn idem_keys_last_a_day_per_mailbox() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(&d.path().join("work.db"), 1 << 30).unwrap();
        s.set_idem("a", "k", "id1", 1000, "h").unwrap();
        assert_eq!(s.idem("a", "k", 500).unwrap(), Some(("id1".into(), "h".into())));
        assert_eq!(s.idem("b", "k", 500).unwrap(), None, "another mailbox's key");
        assert_eq!(s.idem("a", "k", 1001).unwrap(), None, "too old: forgotten");
        assert_eq!(s.idem("a", "k", 0).unwrap(), None, "and deleted");
    }
}
