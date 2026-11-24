//! The Postgres server the store tests run on, and the docker calls that
//! start it.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sidecar_node::postgres::PostgresStore;
use sqlx::Connection;
use sqlx::postgres::{PgConnectOptions, PgConnection};

// The test database. The Postgres tests need a real server;
// they use the one `SIDECAR_TEST_POSTGRES_URL` names (a `postgres://` URL
// whose user may create schemas), or else start one Postgres container per
// test binary (the image e2e/run.sh pins, PG_IMAGE), under a unique name
// (`sidecar-<label>-<pid>-<time>`) on a port docker picks on 127.0.0.1, and
// remove it with `docker rm -f` when the server guard drops, also when the
// test fails. Every store gets a fresh schema of its own, as each deployed
// node has a database of its own, so stores never see each other's rows;
// with a given server the schemas are dropped at the end. Without docker and
// without the variable the test prints that it was skipped and passes,
// unless PSS_REQUIRE_POSTGRES=1, which turns the skip into a
// failure (for CI). A run killed outright can leave its container behind:
// `docker ps --filter name=sidecar-<label>` finds it.
pub const URL_VAR: &str = "SIDECAR_TEST_POSTGRES_URL";
pub const REQUIRE_VAR: &str = "PSS_REQUIRE_POSTGRES";

/// Held shared while a test has a store's lock files open, exclusively for a
/// process spawn. A spawned child holds a copy of every descriptor the test
/// process has open, the store locks among them, until its exec closes them;
/// a store a test closes and reopens in that window is still locked, and the
/// reopen is refused as "open in another process". So [`docker`] spawns only
/// while no such test runs.
pub static SPAWN: RwLock<()> = RwLock::new(());

/// Run `docker` and wait for it; the spawn holds [`SPAWN`] exclusively.
pub fn docker(args: &[&str]) -> Result<String, String> {
    let child = {
        let _spawning = SPAWN.write().unwrap_or_else(PoisonError::into_inner);
        Command::new("docker")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    };
    let out = child
        .and_then(|c| c.wait_with_output())
        .map_err(|e| format!("docker: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub use crate::block_on as block;

/// A server the test may create schemas on; removes what it created.
pub struct PgServer {
    options: PgConnectOptions,
    container: Option<String>,
    schema_prefix: String,
    schemas: Vec<String>,
}

impl PgServer {
    /// Connect options of the server's default schema.
    pub fn options(&self) -> &PgConnectOptions {
        &self.options
    }

    /// A fresh, empty schema and connect options that use it.
    pub fn fresh(&mut self) -> PgConnectOptions {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let schema = format!(
            "{}_{}_{}",
            self.schema_prefix,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        block(async {
            let mut c = connect(&self.options).await;
            sqlx::query(&format!("CREATE SCHEMA {schema}"))
                .execute(&mut c)
                .await
                .expect("creating a test schema");
            let _ = c.close().await;
        });
        self.schemas.push(schema.clone());
        self.options
            .clone()
            .options([("search_path", schema.as_str())])
    }

    /// A store on a fresh schema.
    pub fn store(&mut self) -> PostgresStore {
        PostgresStore::connect_with(self.fresh(), 4).unwrap()
    }
}

async fn connect(options: &PgConnectOptions) -> PgConnection {
    PgConnection::connect_with(options)
        .await
        .expect("connecting to the test server")
}

impl Drop for PgServer {
    fn drop(&mut self) {
        match &self.container {
            Some(name) => {
                let _ = docker(&["rm", "-f", name]);
            }
            None => {
                let schemas = std::mem::take(&mut self.schemas);
                block(async {
                    let mut c = connect(&self.options).await;
                    for schema in schemas {
                        let _ = sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
                            .execute(&mut c)
                            .await;
                    }
                    let _ = c.close().await;
                });
            }
        }
    }
}

/// The test server for the tests labelled `label` (the container's and the
/// schemas' name), or `None` (with the reason printed) when there is none.
pub fn postgres_server(label: &str) -> Option<PgServer> {
    let schema_prefix = label.replace('-', "_");
    if let Ok(url) = std::env::var(URL_VAR) {
        eprintln!("postgres: using the server {URL_VAR} names");
        return Some(PgServer {
            options: url.parse().expect("SIDECAR_TEST_POSTGRES_URL parses"),
            container: None,
            schema_prefix,
            schemas: Vec::new(),
        });
    }
    if let Err(why) = docker(&["info", "--format", "{{.ServerVersion}}"]) {
        let message = format!(
            "SKIPPED: the Postgres tests did not run: docker is unavailable ({why}) and \
             {URL_VAR} is not set"
        );
        if std::env::var(REQUIRE_VAR).as_deref() == Ok("1") {
            panic!("{message}, and {REQUIRE_VAR}=1");
        }
        eprintln!("{message}");
        return None;
    }
    let name = format!(
        "sidecar-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    docker(&[
        "run",
        "-d",
        "--rm",
        "--name",
        &name,
        "-e",
        "POSTGRES_PASSWORD=postgres",
        "-p",
        "127.0.0.1::5432",
        "postgres:16.14-alpine3.24@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777",
    ])
    .unwrap_or_else(|e| panic!("starting the Postgres container: {e}"));
    // From here on the guard removes the container, whatever happens.
    let mut server = PgServer {
        options: PgConnectOptions::new(),
        container: Some(name.clone()),
        schema_prefix,
        schemas: Vec::new(),
    };
    let port = docker(&["port", &name, "5432/tcp"]).expect("the container's port");
    let port: u16 = port
        .lines()
        .next()
        .and_then(|l| l.rsplit(':').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no port in `{port}`"));
    server.options = PgConnectOptions::new()
        .host("127.0.0.1")
        .port(port)
        .username("postgres")
        .password("postgres")
        .database("postgres");
    let start = Instant::now();
    loop {
        let ready = block(async {
            let mut c = PgConnection::connect_with(&server.options).await.ok()?;
            sqlx::query("SELECT 1").execute(&mut c).await.ok()?;
            c.close().await.ok()
        });
        if ready.is_some() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the Postgres container {name} did not come up in 60 s"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!(
        "postgres: container {name} on 127.0.0.1:{port}, up in {:.1} s",
        start.elapsed().as_secs_f64()
    );
    Some(server)
}
