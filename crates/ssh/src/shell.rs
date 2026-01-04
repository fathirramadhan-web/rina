//! Interactive PTY shell sessions.
//!
//! The channel is split: one task pumps output into an event callback, the
//! write half is driven by a command queue, so heavy output never blocks
//! keystrokes and vice-versa.

use russh::{ChannelMsg, Pty};
use tokio::sync::mpsc;

use crate::client::SshConnection;
use crate::error::Result;

#[derive(Debug, Clone)]
pub enum ShellEvent {
    /// Terminal output (stdout+stderr interleaved).
    Data(Vec<u8>),
    /// The remote shell exited / channel closed.
    Closed { exit_status: Option<u32> },
}

pub struct ShellOptions {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
}

impl Default for ShellOptions {
    fn default() -> Self {
        Self { term: "xterm-256color".into(), cols: 80, rows: 24 }
    }
}

enum Cmd {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
}

/// Cheap, cloneable handle used to drive a running shell.
#[derive(Clone)]
pub struct ShellHandle {
    tx: mpsc::UnboundedSender<Cmd>,
}

impl ShellHandle {
    pub fn write(&self, data: impl Into<Vec<u8>>) -> bool {
        self.tx.send(Cmd::Data(data.into())).is_ok()
    }

    pub fn resize(&self, cols: u32, rows: u32) -> bool {
        self.tx.send(Cmd::Resize(cols, rows)).is_ok()
    }

    pub fn close(&self) -> bool {
        self.tx.send(Cmd::Close).is_ok()
    }
}

/// Request a PTY + shell on `conn` and pump events to `on_event`.
pub async fn open_shell<F>(
    conn: &SshConnection,
    opts: ShellOptions,
    on_event: F,
) -> Result<ShellHandle>
where
    F: Fn(ShellEvent) + Send + 'static,
{
    let channel = conn.handle.channel_open_session().await?;
    channel
        .request_pty(true, &opts.term, opts.cols, opts.rows, 0, 0, &[(Pty::ECHO, 1)])
        .await?;
    channel.request_shell(true).await?;

    let (mut reader, writer) = channel.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Cmd>();

    // Writer task: keystrokes, resizes, close.
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            let res = match cmd {
                Cmd::Data(d) => writer.data(&d[..]).await,
                Cmd::Resize(cols, rows) => writer.window_change(cols, rows, 0, 0).await,
                Cmd::Close => {
                    let _ = writer.eof().await;
                    break;
                }
            };
            if let Err(e) = res {
                tracing::warn!("shell write error: {e}");
                break;
            }
        }
    });

    // Reader task: forward output to the event callback.
    tokio::spawn(async move {
        let mut exit_status = None;
        while let Some(msg) = reader.wait().await {
            match msg {
                ChannelMsg::Data { data } => on_event(ShellEvent::Data(data.to_vec())),
                ChannelMsg::ExtendedData { data, .. } => on_event(ShellEvent::Data(data.to_vec())),
                ChannelMsg::ExitStatus { exit_status: s } => exit_status = Some(s),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        on_event(ShellEvent::Closed { exit_status });
    });

    Ok(ShellHandle { tx })
}
