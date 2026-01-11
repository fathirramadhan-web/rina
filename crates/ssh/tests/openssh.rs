//! Real SSH round-trip tests against an in-process `russh` **server**.
//!
//! This is a genuine SSH exchange (real handshake, crypto, auth, channel,
//! SFTP subsystem) driven by the rina-ssh client — not a mock of the client.
//! No Docker or system sshd is required.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rina_ssh::client::connect as ssh_connect;
use rina_ssh::{
    AuthMethod, ConnectConfig, HostKeyInfo, HostKeyStore, Interaction, MemHostKeyStore,
    ShellEvent, ShellOptions, SshError,
};
use russh::server::{Auth, Msg, Server as _, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Name, OpenFlags, StatusCode, Status, SftpHandle,
};
use russh_sftp::server::{run as sftp_run, Handler as SftpHandler};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const USER: &str = "testuser";
const PASS: &str = "correct-horse-battery";
const WRONG_PASS: &str = "nope";

fn reject() -> Auth {
    Auth::Reject {
        proceed_with_methods: None,
        partial_success: false,
    }
}

// ---------------------------------------------------------------- server

/// Minimal in-memory filesystem backing the SFTP subsystem.
#[derive(Clone, Default)]
struct MemFs {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    dirs: Arc<Mutex<Vec<String>>>,
    dir_read_done: Arc<AtomicBool>,
}

#[derive(Clone)]
struct TestServer {
    fs: MemFs,
}

impl russh::server::Server for TestServer {
    type Handler = TestSession;

    fn new_client(&mut self, _addr: Option<SocketAddr>) -> Self::Handler {
        TestSession {
            fs: self.fs.clone(),
            channels: Arc::new(Mutex::new(HashMap::new())),
            shells: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }
}

struct TestSession {
    fs: MemFs,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    shells: Arc<Mutex<std::collections::HashSet<ChannelId>>>,
}

impl russh::server::Handler for TestSession {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == USER && password == PASS {
            Ok(Auth::Accept)
        } else {
            Ok(reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col: u32,
        _row: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shells.lock().await.insert(channel);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        _col: u32,
        _row: u32,
        _pw: u32,
        _ph: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        // Echo a marker so the test can confirm the server saw the resize.
        session.data(channel, &b"[resized]\r\n"[..])?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Echo only on shell channels. SFTP channels carry a binary packet
        // stream; echoing there corrupts the SFTP framing.
        if !self.shells.lock().await.contains(&channel) {
            return Ok(());
        }
        // Act as a toy shell: echo each line back with a prefix.
        let line = String::from_utf8_lossy(data);
        for cmd in line.split('\n') {
            let cmd = cmd.trim_end_matches('\r').trim();
            if cmd.is_empty() {
                continue;
            }
            if let Some(code) = cmd.strip_prefix("exit ") {
                session.exit_status_request(channel, code.trim().parse().unwrap_or(0))?;
                session.close(channel)?;
                return Ok(());
            }
            let reply = format!("[out] {cmd}\r\n");
            session.data(channel, reply.into_bytes())?;
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let channel = self.channels.lock().await.remove(&channel_id).unwrap();
        session.channel_success(channel_id)?;
        let fs = self.fs.clone();
        sftp_run(channel.into_stream(), fs).await;
        Ok(())
    }
}

// ---------------------------------------------------------------- SFTP handler

impl SftpHandler for MemFs {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn realpath(&mut self, id: u32, _path: String) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![File::dummy("/")],
        })
    }

    async fn open(
        &mut self,
        _id: u32,
        filename: String,
        _pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        Ok(russh_sftp::protocol::Handle {
            id: _id,
            handle: filename.into(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let path = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let mut files = self.files.lock().await;
        let entry = files.entry(path).or_default();
        let need = offset as usize + data.len();
        if entry.len() < need {
            entry.resize(need, 0);
        }
        entry[offset as usize..need].copy_from_slice(&data);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let path = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let files = self.files.lock().await;
        let Some(bytes) = files.get(&path) else {
            return Err(StatusCode::NoSuchFile);
        };
        let off = offset as usize;
        if off >= bytes.len() {
            return Err(StatusCode::Eof);
        }
        let end = (off + len as usize).min(bytes.len());
        Ok(Data {
            id,
            data: bytes[off..end].to_vec(),
        })
    }

    async fn close(&mut self, id: u32, _handle: SftpHandle) -> Result<Status, Self::Error> {
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }

    async fn opendir(&mut self, id: u32, _path: String) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        self.dir_read_done.store(false, Ordering::SeqCst);
        Ok(russh_sftp::protocol::Handle {
            id,
            handle: "/".into(),
        })
    }

    async fn readdir(&mut self, id: u32, _handle: SftpHandle) -> Result<Name, Self::Error> {
        if self.dir_read_done.swap(true, Ordering::SeqCst) {
            return Err(StatusCode::Eof);
        }
        let files = self.files.lock().await;
        let dirs = self.dirs.lock().await;
        let mut out: Vec<File> = files
            .keys()
            .map(|p| File::new(p.clone(), FileAttributes::default()))
            .collect();
        out.extend(
            dirs.iter()
                .map(|d| File::new(d.clone(), FileAttributes::default())),
        );
        Ok(Name { id, files: out })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        self.files.lock().await.remove(&filename);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.dirs.lock().await.push(path);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        self.dirs.lock().await.retain(|d| d != &path);
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let mut files = self.files.lock().await;
        if let Some(v) = files.remove(&oldpath) {
            files.insert(newpath, v);
        }
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let files = self.files.lock().await;
        let size = files.get(&path).map(|v| v.len()).unwrap_or(0) as u64;
        Ok(Attrs {
            id,
            attrs: FileAttributes {
                size: Some(size),
                ..Default::default()
            },
        })
    }
}

// ---------------------------------------------------------------- harness

struct SpawnedServer {
    port: u16,
}

async fn spawn_server() -> SpawnedServer {
    let mut srv = TestServer {
        fs: MemFs::default(),
    };
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(russh::server::Config {
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![russh::keys::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap()],
        ..Default::default()
    });
    // Server + listener must live for the whole session; move into the task.
    tokio::spawn(async move {
        let _ = srv.run_on_socket(config, &listener).await;
    });
    SpawnedServer { port }
}

fn connect_cfg(port: u16) -> ConnectConfig {
    ConnectConfig {
        host: "127.0.0.1".into(),
        port,
        username: USER.into(),
        keepalive_secs: 30,
    }
}

/// Interaction that returns a fixed password and counts host-key prompts.
struct FixedPw {
    pw: String,
    accept_host_key_calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Interaction for FixedPw {
    async fn password(&self, _prompt: &str) -> rina_ssh::Result<String> {
        Ok(self.pw.clone())
    }
    async fn kbd_prompt(
        &self,
        _name: &str,
        _instruction: &str,
        _prompt: &str,
    ) -> rina_ssh::Result<String> {
        Ok(self.pw.clone())
    }
    async fn accept_host_key(&self, _info: &HostKeyInfo, _changed: bool) -> rina_ssh::Result<bool> {
        self.accept_host_key_calls.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}

/// Collects ShellEvents from the pump task.
#[derive(Clone, Default)]
struct Collector {
    data: Arc<Mutex<Vec<u8>>>,
    closed: Arc<Mutex<Option<Option<u32>>>>,
}

impl Collector {
    fn new() -> (Self, impl Fn(ShellEvent) + Send + 'static) {
        let c = Collector::default();
        let cb = {
            let c = c.clone();
            move |ev: ShellEvent| match ev {
                ShellEvent::Data(d) => {
                    if let Ok(mut g) = c.data.try_lock() {
                        g.extend_from_slice(&d);
                    }
                }
                ShellEvent::Closed { exit_status } => {
                    if let Ok(mut g) = c.closed.try_lock() {
                        *g = Some(exit_status);
                    }
                }
            }
        };
        (c, cb)
    }

    async fn contains(&self, needle: &str) -> bool {
        let g = self.data.lock().await;
        g.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    /// Poll until `needle` appears in the stream or the timeout elapses.
    async fn wait_for(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.contains(needle).await {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn closed(&self) -> Option<Option<u32>> {
        *self.closed.lock().await
    }
}

/// Helper: connect with the good password and a fresh host-key store.
async fn connect_ok(port: u16) -> rina_ssh::SshConnection {
    let interaction = Arc::new(FixedPw {
        pw: PASS.into(),
        accept_host_key_calls: Arc::new(AtomicUsize::new(0)),
    });
    ssh_connect(
        &connect_cfg(port),
        AuthMethod::Password(PASS.into()),
        interaction,
        Arc::new(MemHostKeyStore::default()),
    )
    .await
    .expect("connect with correct password should succeed")
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn password_auth_connect_succeeds() {
    let s = spawn_server().await;
    let conn = connect_ok(s.port).await;
    assert!(!conn.is_closed());
}

#[tokio::test]
async fn wrong_password_fails_with_auth_error() {
    let s = spawn_server().await;
    let interaction = Arc::new(FixedPw {
        pw: WRONG_PASS.into(),
        accept_host_key_calls: Arc::new(AtomicUsize::new(0)),
    });
    let result = ssh_connect(
        &connect_cfg(s.port),
        AuthMethod::Password(WRONG_PASS.into()),
        interaction,
        Arc::new(MemHostKeyStore::default()),
    )
    .await;
    match result {
        Err(e) => assert!(
            matches!(e, SshError::Auth(_)),
            "expected Auth error, got {e:?}"
        ),
        Ok(_) => panic!("wrong password should not authenticate"),
    }
}

#[tokio::test]
async fn open_shell_echoes_and_data_flows_both_directions() {
    let s = spawn_server().await;
    let conn = connect_ok(s.port).await;

    let (collector, cb) = Collector::new();
    let handle = rina_ssh::shell::open_shell(&conn, ShellOptions::default(), cb)
        .await
        .unwrap();

    // client -> server: write a command; server -> client: read echo back.
    handle.write("echo hello\r\n");
    assert!(
        collector
            .wait_for("[out] echo hello", Duration::from_secs(5))
            .await,
        "expected echoed command, got: {:?}",
        String::from_utf8_lossy(&collector.data.lock().await)
    );
    handle.close();
}

#[tokio::test]
async fn pty_resize_is_accepted_and_shell_still_works() {
    let s = spawn_server().await;
    let conn = connect_ok(s.port).await;

    let (collector, cb) = Collector::new();
    let handle = rina_ssh::shell::open_shell(&conn, ShellOptions::default(), cb)
        .await
        .unwrap();

    assert!(
        handle.resize(80, 24),
        "resize command should be queued without error"
    );
    assert!(
        collector.wait_for("[resized]", Duration::from_secs(5)).await,
        "server should have observed window-change"
    );
    // shell still works after resize
    handle.write("echo after\r\n");
    assert!(
        collector
            .wait_for("[out] echo after", Duration::from_secs(5))
            .await,
        "shell should still echo after resize"
    );
    handle.close();
}

#[tokio::test]
async fn exit_status_is_carried_in_closed_event() {
    let s = spawn_server().await;
    let conn = connect_ok(s.port).await;

    let (collector, cb) = Collector::new();
    let handle = rina_ssh::shell::open_shell(&conn, ShellOptions::default(), cb)
        .await
        .unwrap();

    handle.write("exit 7\r\n");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for Closed event"
        );
        if let Some(status) = collector.closed().await {
            assert_eq!(status, Some(7), "expected exit status 7");
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn tofu_pins_key_then_reconnect_succeeds_without_prompt() {
    let s = spawn_server().await;

    // First connect: prompt once (TOFU), pin the key.
    let first_calls = Arc::new(AtomicUsize::new(0));
    let interaction = Arc::new(FixedPw {
        pw: PASS.into(),
        accept_host_key_calls: first_calls.clone(),
    });
    let store = Arc::new(MemHostKeyStore::default());
    ssh_connect(
        &connect_cfg(s.port),
        AuthMethod::Password(PASS.into()),
        interaction,
        store.clone(),
    )
    .await
    .expect("first connect (TOFU) should succeed");

    assert_eq!(
        first_calls.load(Ordering::SeqCst),
        1,
        "host-key prompt should fire exactly once on first use"
    );
    assert!(
        store.pinned("127.0.0.1", s.port).await.is_some(),
        "key should be pinned after first connect"
    );

    // Second connect with the SAME store: no prompt.
    let second_calls = Arc::new(AtomicUsize::new(0));
    let interaction2 = Arc::new(FixedPw {
        pw: PASS.into(),
        accept_host_key_calls: second_calls.clone(),
    });
    let conn2 = ssh_connect(
        &connect_cfg(s.port),
        AuthMethod::Password(PASS.into()),
        interaction2,
        store.clone(),
    )
    .await
    .expect("second connect with pinned key should succeed");
    assert!(!conn2.is_closed());
    assert_eq!(
        second_calls.load(Ordering::SeqCst),
        0,
        "no host-key prompt expected when key already pinned"
    );
}

#[tokio::test]
async fn sftp_write_read_list_rename_delete_mkdir_rmdir() {
    let s = spawn_server().await;
    let conn = connect_ok(s.port).await;

    let sftp = rina_ssh::sftp::SftpClient::open(&conn.handle).await.unwrap();

    // write + read back
    sftp.write_file("/hello.txt", b"hello sftp world")
        .await
        .unwrap();
    let got = sftp.read_file("/hello.txt").await.unwrap();
    assert_eq!(got, b"hello sftp world");

    // read_dir shows it
    let entries = sftp.read_dir("/").await.unwrap();
    assert!(
        entries.iter().any(|e| e.name == "/hello.txt"),
        "hello.txt should appear in read_dir, got {:?}",
        entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
    );

    // rename
    sftp.rename("/hello.txt", "/renamed.txt").await.unwrap();
    let got2 = sftp.read_file("/renamed.txt").await.unwrap();
    assert_eq!(got2, b"hello sftp world");

    // mkdir + rmdir
    sftp.create_dir("/tmpdir").await.unwrap();
    sftp.remove_dir("/tmpdir").await.unwrap();

    // delete
    sftp.remove_file("/renamed.txt").await.unwrap();

    sftp.close().await.unwrap();
}
