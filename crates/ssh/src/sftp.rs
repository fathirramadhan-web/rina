//! SFTP file operations over an SSH channel.

use russh::Channel;
use russh::client::Msg;
use russh_sftp::client::SftpSession;

use crate::error::{Result, SshError};

/// An open SFTP session on a dedicated subsystem channel.
pub struct SftpClient {
    sftp: SftpSession,
}

impl SftpClient {
    /// Open the SFTP subsystem on `conn`.
    pub async fn open(conn: &russh::client::Handle<impl russh::client::Handler>) -> Result<Self> {
        let channel: Channel<Msg> = conn.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let stream = channel.into_stream();
        let sftp = SftpSession::new(stream)
            .await
            .map_err(|e| SshError::Sftp(e.to_string()))?;
        Ok(Self { sftp })
    }

    /// List a directory.
    pub async fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        let dir = self.sftp.read_dir(path).await.map_err(sftp_err)?;
        let mut out = Vec::new();
        for entry in dir {
            let entry = entry.map_err(sftp_err)?;
            out.push(DirEntry {
                name: entry.file_name(),
                is_dir: entry.metadata.is_dir(),
                is_symlink: entry.metadata.is_symlink(),
                size: entry.metadata.len().unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Read a whole file into memory (small files only).
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.sftp.read(path).await.map_err(sftp_err)
    }

    /// Write a whole file (creates/truncates).
    pub async fn write_file(&self, path: &str, data: &[u8]) -> Result<()> {
        self.sftp.write(path, data).await.map_err(sftp_err)
    }

    pub async fn create_dir(&self, path: &str) -> Result<()> {
        self.sftp.create_dir(path).await.map_err(sftp_err)
    }

    pub async fn remove_file(&self, path: &str) -> Result<()> {
        self.sftp.remove_file(path).await.map_err(sftp_err)
    }

    pub async fn remove_dir(&self, path: &str) -> Result<()> {
        self.sftp.remove_dir(path).await.map_err(sftp_err)
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.sftp.rename(from, to).await.map_err(sftp_err)
    }

    /// Canonical absolute path of `path`.
    pub async fn canonicalize(&self, path: &str) -> Result<String> {
        let s = self.sftp.canonicalize(path).await.map_err(sftp_err)?;
        Ok(s.to_string_lossy().into_owned())
    }

    /// Set permissions on a path (octal, e.g. 0o755).
    pub async fn set_permissions(&self, path: &str, mode: u32) -> Result<()> {
        let attrs = russh_sftp::protocol::FileAttributes::default().with_permissions(mode);
        self.sftp.set_metadata(path, attrs).await.map_err(sftp_err)
    }

    pub async fn close(&self) -> Result<()> {
        self.sftp.close().await.map_err(sftp_err)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
}

fn sftp_err(e: russh_sftp::Error) -> SshError {
    SshError::Sftp(e.to_string())
}
