//! The operator's admin socket, as the node and the orchestrator both serve
//! it: a Unix domain socket, never a TLS listener or a network port, carrying
//! one JSON object per line each way. Who may use it is decided by file
//! permissions: its directory is created 0700 and the socket set to 0600, so
//! only the process's own OS user (and root) can connect; there is no further
//! authentication. At bind a stale socket left by a process that exited is
//! removed, and a live process answering on it is refused. Each binary keeps
//! its own request and response types and its own handler.

use std::future::Future;
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use eyre::{Context, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sidecar_core::Refusal;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// The admin socket's file name, when a config names no path.
pub const ADMIN_SOCKET_FILE: &str = "admin.sock";

/// The longest Unix socket path the kernel accepts (`sun_path` is 108 bytes
/// with the terminating NUL).
const MAX_SOCKET_PATH: usize = 107;

/// `path` with `.` and `name/..` pairs removed, without touching the file
/// system: a config three directories down names `../../../data/run/node0`,
/// and an admin socket's path must stay short.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// Refuse a socket path the kernel cannot bind (longer than
/// [`MAX_SOCKET_PATH`] bytes); `fix` names the config fields that shorten it.
pub fn check_path(path: &Path, fix: &str) -> eyre::Result<()> {
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH {
        bail!(
            "the admin socket path {} is {len} bytes; a Unix socket path holds at most \
             {MAX_SOCKET_PATH}: {fix}",
            path.display()
        );
    }
    Ok(())
}

/// Bind the admin socket at `path`: create its directory, or tighten an
/// existing one, to 0700 (so no other user can reach the socket in the
/// moment between the bind and the chmod), replace a stale socket, bind and
/// restrict it to the owner (0600). `who` names the process in the refusal
/// when another one already answers on it.
pub fn bind(path: &Path, who: &str) -> eyre::Result<UnixListener> {
    check_path(path, "set a shorter path")?;
    if let Some(dir) = path.parent() {
        sidecar_core::keys::create_private_dir(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    if path.exists() {
        use std::os::unix::fs::FileTypeExt;
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_socket() {
            bail!("{} exists and is not a socket", path.display());
        }
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            bail!(
                "another process answers on the admin socket {}; is the {who} already running?",
                path.display()
            );
        }
        std::fs::remove_file(path)
            .with_context(|| format!("removing the stale socket {}", path.display()))?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding the admin socket {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;
    Ok(listener)
}

/// Serve admin commands on `listener` until the task is aborted: each line
/// is parsed as a `Req` and answered by `handle`, a line that does not parse
/// with `handle(Err(refusal))` (400 naming the field); blank lines are
/// skipped. Each line's buffer is overwritten once parsed, since a command
/// may carry key material.
pub async fn serve<Req, Resp, H, Fut>(listener: UnixListener, handle: H)
where
    Req: DeserializeOwned + Send + 'static,
    Resp: Serialize + Send + 'static,
    H: Fn(Result<Req, Refusal>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Resp> + Send + 'static,
{
    let handle = Arc::new(handle);
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!(error = %e, "admin socket: accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let handle = handle.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, &*handle).await {
                tracing::debug!(error = %e, "admin socket: connection ended with an error");
            }
        });
    }
}

async fn serve_connection<Req, Resp, H, Fut>(stream: UnixStream, handle: &H) -> std::io::Result<()>
where
    Req: DeserializeOwned,
    Resp: Serialize,
    H: Fn(Result<Req, Refusal>) -> Fut,
    Fut: Future<Output = Resp>,
{
    let (read, mut write) = stream.into_split();
    let mut lines = tokio::io::BufReader::new(read).lines();
    while let Some(mut line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let parsed = sidecar_core::error::parse_json::<Req>(&line);
        wipe(&mut line);
        let response = handle(parsed).await;
        let mut out = serde_json::to_vec(&response).expect("an admin response serialises");
        out.push(b'\n');
        write.write_all(&out).await?;
    }
    Ok(())
}

/// Overwrite `text`'s bytes with zeros before it is freed.
fn wipe(text: &mut String) {
    use zeroize::Zeroize;
    text.zeroize();
}

/// Send one command to the admin socket at `path` and read its answer
/// (blocking). `whose` names the socket's process in the connect error.
pub fn call<Req: Serialize, Resp: DeserializeOwned>(
    path: &Path,
    whose: &str,
    req: &Req,
) -> eyre::Result<Resp> {
    let mut stream = std::os::unix::net::UnixStream::connect(path).with_context(|| {
        format!(
            "connecting to the {whose} admin socket {} (is it running?)",
            path.display()
        )
    })?;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    zeroize::Zeroize::zeroize(&mut line);
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut answer = String::new();
    BufReader::new(stream).read_line(&mut answer)?;
    serde_json::from_str(answer.trim())
        .with_context(|| format!("the admin socket answered `{}`", answer.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
    enum Req {
        Echo { n: u64 },
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct Resp {
        n: Option<u64>,
        refused: Option<String>,
    }

    #[test]
    fn normalize_drops_dot_and_parent_pairs() {
        assert_eq!(normalize(Path::new("/a/b/./c/../../d")), Path::new("/a/d"));
        assert_eq!(normalize(Path::new("../x/../y")), Path::new("../y"));
        assert_eq!(
            normalize(Path::new("/srv/cfg/a/b/../../../data/run/admin.sock")),
            Path::new("/srv/data/run/admin.sock")
        );
    }

    #[test]
    fn a_path_past_the_kernel_limit_is_refused() {
        let long = PathBuf::from(format!("/{}", "a".repeat(MAX_SOCKET_PATH)));
        let e = check_path(&long, "shorten it").unwrap_err().to_string();
        assert!(e.contains("shorten it"), "{e}");
        check_path(Path::new("/run/admin.sock"), "").unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_command_is_answered_and_a_bad_one_refused() {
        // The tests' scratch root (sidecar-test-fixtures' `dirs::tmp_root`,
        // which this crate cannot depend on): TXE_TMP_ROOT, default
        // .runs/tmp in the repository.
        let root = std::env::var_os("TXE_TMP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .ancestors()
                    .nth(2)
                    .expect("the repository root")
                    .join(".runs/tmp")
            });
        let dir = root.join(format!("admin-{}", std::process::id()));
        let path = dir.join("run").join(ADMIN_SOCKET_FILE);
        let listener = bind(&path, "test").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert!(
            bind(&path, "test")
                .unwrap_err()
                .to_string()
                .contains("already running")
        );
        let task = tokio::spawn(serve(listener, |req: Result<Req, Refusal>| async move {
            match req {
                Ok(Req::Echo { n }) => Resp {
                    n: Some(n),
                    refused: None,
                },
                Err(r) => Resp {
                    n: None,
                    refused: Some(r.message),
                },
            }
        }));
        let p = path.clone();
        let (ok, bad) = tokio::task::spawn_blocking(move || {
            let ok: Resp = call(&p, "test", &Req::Echo { n: 7 }).unwrap();
            let bad: Resp = call(&p, "test", &serde_json::json!({"op": "nope"})).unwrap();
            (ok, bad)
        })
        .await
        .unwrap();
        assert_eq!(ok.n, Some(7));
        assert!(bad.refused.is_some_and(|m| m.contains("nope")));
        task.abort();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
