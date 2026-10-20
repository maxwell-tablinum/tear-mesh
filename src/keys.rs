//! Owner keys made and used in this process: the menu and setup take the passphrase themselves,
//! so the person never leaves the screen. Keys are ordinary OpenSSH files, and signatures are
//! exactly what `ssh-keygen -Y sign` writes. Security keys (sk-ssh-ed25519) still sign with
//! ssh-keygen, which talks to the device.

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use ssh_key::private::KeypairData;
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, Cipher, HashAlg, Kdf, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::mesh::SIG_NAMESPACE;

/// bcrypt rounds for new keys, as `ssh-keygen -a 100`.
const ROUNDS: u32 = 100;
/// EFF's large wordlist (7776 words), CC BY 3.0 US, from
/// eff.org/deeplinks/2016/07/new-wordlists-random-passphrases.
const WORDLIST: &str = include_str!("eff_large_wordlist.txt");
/// Words in a generated passphrase: 6 × log2(7776) ≈ 77.5 bits.
const WORDS: usize = 6;

/// A new key, encrypted, as the files `ssh-keygen` would write.
#[derive(Clone, Debug, PartialEq)]
pub struct NewKey {
    pub private: Zeroizing<String>,
    pub public: String,
}

/// A new ed25519 key encrypted with `pass`, and the open key to sign with right away.
pub fn generate(comment: &str, pass: &str) -> Result<(PrivateKey, NewKey)> {
    let mut k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    k.set_comment(comment);
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let enc = k.encrypt_with(
        Cipher::Aes256Ctr,
        Kdf::Bcrypt { salt, rounds: ROUNDS },
        OsRng.next_u32(),
        pass,
    )?;
    let private = Zeroizing::new(enc.to_openssh(LineEnding::LF)?.to_string());
    let public = k.public_key().to_openssh()?;
    Ok((k, NewKey { private, public }))
}

/// How an owner key file can sign.
#[derive(Debug, PartialEq)]
pub enum Signer {
    /// Here, in this process; `encrypted` says whether it needs a passphrase.
    Here { encrypted: bool },
    /// With `ssh-keygen` in a terminal: a security key, or a file this can't read.
    Outside,
}

pub fn signer(key: &Path) -> Signer {
    match PrivateKey::read_openssh_file(key) {
        Ok(k) if k.algorithm() == Algorithm::Ed25519 => Signer::Here {
            encrypted: k.is_encrypted(),
        },
        _ => Signer::Outside,
    }
}

/// Reads a key file, opening it with `pass` if it has one.
pub fn open(key: &Path, pass: &str) -> Result<PrivateKey> {
    let k = PrivateKey::read_openssh_file(key).with_context(|| format!("reading {}", key.display()))?;
    if !k.is_encrypted() {
        return Ok(k);
    }
    match k.decrypt(pass) {
        Ok(k) => Ok(k),
        Err(ssh_key::Error::Crypto) => bail!("that passphrase doesn't open {}", key.display()),
        Err(e) => Err(e.into()),
    }
}

/// The `.sig` text `ssh-keygen -Y sign -n tear-mesh-membership` writes for `toml`.
pub fn sign(key: &PrivateKey, toml: &str) -> Result<String> {
    ensure!(
        matches!(key.key_data(), KeypairData::Ed25519(_)),
        "only ed25519 keys sign here"
    );
    Ok(key
        .sign(SIG_NAMESPACE, HashAlg::Sha512, toml.as_bytes())?
        .to_pem(LineEnding::LF)?)
}

/// A random passphrase of `WORDS` words from the EFF list, joined with `-`.
pub fn passphrase() -> Zeroizing<String> {
    let words: Vec<&str> = WORDLIST.lines().filter_map(|l| l.split('\t').nth(1)).collect();
    let mut out = Zeroizing::new(String::with_capacity(WORDS * 10));
    for i in 0..WORDS {
        if i > 0 {
            out.push('-');
        }
        out.push_str(words[pick(words.len() as u32) as usize]);
    }
    out
}

/// A uniform number below `n`, by rejection sampling (a plain `%` would favor small numbers).
fn pick(n: u32) -> u32 {
    let zone = u32::MAX - u32::MAX % n;
    loop {
        let x = OsRng.next_u32();
        if x < zone {
            return x % n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn wordlist_and_passphrases() {
        let words: Vec<&str> = WORDLIST.lines().filter_map(|l| l.split('\t').nth(1)).collect();
        assert_eq!(words.len(), 7776);
        let p = passphrase();
        assert_eq!(p.split('-').count(), WORDS);
        assert!(p.split('-').all(|w| words.contains(&w)));
        assert_ne!(*p, *passphrase());
        assert!((0..1000).all(|_| pick(7) < 7));
    }

    #[test]
    fn keys_open_with_their_passphrase_and_sign_like_ssh_keygen() {
        let d = tempfile::tempdir().unwrap();
        let (open_key, k) = generate("tearmesh test", "correct horse").unwrap();
        let f = d.path().join("k");
        std::fs::write(&f, k.private.as_bytes()).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert_eq!(signer(&f), Signer::Here { encrypted: true });
        assert!(format!("{:#}", open(&f, "wrong").unwrap_err()).contains("doesn't open"));
        let opened = open(&f, "correct horse").unwrap();
        assert_eq!(opened.public_key().key_data(), open_key.public_key().key_data());

        // ssh-keygen reads the file with the passphrase.
        let out = Command::new("ssh-keygen").args(["-y", "-P", "correct horse", "-f"]).arg(&f).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(k.public.starts_with(String::from_utf8_lossy(&out.stdout).split_whitespace().take(2).collect::<Vec<_>>().join(" ").as_str()));

        // Same bytes as ssh-keygen -Y sign (Ed25519 and SSHSIG are deterministic), and ssh-keygen
        // verifies it.
        let plain = d.path().join("plain");
        std::fs::write(&plain, opened.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&plain, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert_eq!(signer(&plain), Signer::Here { encrypted: false });
        let toml = "name = \"home\"\n";
        let ours = sign(&opened, toml).unwrap();
        let theirs = crate::mesh::tests::sign(d.path(), &plain, toml);
        assert_eq!(ours.trim(), theirs.trim());
        let sigf = d.path().join("m.sig");
        std::fs::write(&sigf, &ours).unwrap();
        let check = |data: &str| {
            let mut c = Command::new("ssh-keygen")
                .args(["-Y", "check-novalidate", "-n", SIG_NAMESPACE, "-s"])
                .arg(&sigf)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            std::io::Write::write_all(c.stdin.as_mut().unwrap(), data.as_bytes()).unwrap();
            drop(c.stdin.take());
            c.wait().unwrap().success()
        };
        assert!(check(toml));
        assert!(!check("name = \"evil\"\n"), "a changed file doesn't verify");

        std::fs::write(d.path().join("junk"), "nope").unwrap();
        assert_eq!(signer(&d.path().join("junk")), Signer::Outside);
    }
}
