use super::*;
use crate::common::StatementCache;
use crate::connection::{MySqlConnection, MySqlConnectionInner};
use crate::io::ReadBuf;
use futures_util::FutureExt;
use std::future::Future;
use std::io;
use std::sync::Mutex;
use std::task::{Context, Poll};

#[derive(Default)]
pub(super) struct Wire {
    pub(super) incoming: VecDeque<u8>,
    pub(super) outgoing: Vec<u8>,
    pub(super) block_write: bool,
    pub(super) read_error: Option<io::ErrorKind>,
}

#[derive(Clone, Default)]
pub(super) struct TestSocket(pub(super) Arc<Mutex<Wire>>);

impl Socket for TestSocket {
    fn try_read(&mut self, buffer: &mut dyn ReadBuf) -> io::Result<usize> {
        let mut wire = self.0.lock().unwrap();
        if let Some(error) = wire.read_error.take() {
            return Err(error.into());
        }
        if wire.incoming.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = buffer.remaining_mut().min(wire.incoming.len());
        let bytes: Vec<_> = wire.incoming.drain(..count).collect();
        buffer.put_slice(&bytes);
        Ok(count)
    }

    fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut wire = self.0.lock().unwrap();
        if wire.block_write {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        wire.outgoing.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn poll_read_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_write_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TestSocket {
    pub(super) fn respond(&self, payload: &[u8]) {
        let mut wire = self.0.lock().unwrap();
        let length = u32::try_from(payload.len()).unwrap().to_le_bytes();
        wire.incoming.extend(&length[..3]);
        wire.incoming.push_back(1);
        wire.incoming.extend(payload);
    }

    pub(super) fn error(&self, number: u16, message: &str) {
        let mut payload = vec![0xff];
        payload.extend(number.to_le_bytes());
        payload.extend(b"#HY000");
        payload.extend(message.as_bytes());
        self.respond(&payload);
    }

    pub(super) fn commands(&self) -> Vec<Vec<u8>> {
        let wire = self.0.lock().unwrap();
        let mut bytes = wire.outgoing.as_slice();
        let mut commands = Vec::new();
        while !bytes.is_empty() {
            let length =
                usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])).unwrap();
            commands.push(bytes[4..4 + length].to_vec());
            bytes = &bytes[4 + length..];
        }
        commands
    }
}

pub(super) fn connection() -> (MySqlConnection, TestSocket) {
    let socket = TestSocket::default();
    let stream = MySqlStream::with_socket(
        CharSet::utf8mb4,
        Collation::utf8mb4_unicode_ci,
        &MySqlConnectOptions::new(),
        socket.clone(),
    )
    .boxed_socket();
    let connection = MySqlConnection {
        inner: Box::new(MySqlConnectionInner {
            stream,
            transaction_depth: 0,
            status_flags: Status::empty(),
            cache_statement: StatementCache::new(8),
            log_settings: Default::default(),
        }),
    };
    (connection, socket)
}

pub(super) fn ready<F: Future>(future: F) -> F::Output {
    future
        .now_or_never()
        .expect("The scripted response must complete without a runtime")
}

pub(super) fn database_error(error: &Error, sql: Option<&str>, number: u16) {
    let native = error
        .as_database_error()
        .unwrap()
        .downcast_ref::<MySqlDatabaseError>();
    assert_eq!(native.sql(), sql);
    assert_eq!(native.number(), number);
    assert_eq!(native.code(), Some("HY000"));
}

pub(super) fn prepare_ok(socket: &TestSocket, parameters: u16) {
    let mut payload = vec![0];
    payload.extend(7_u32.to_le_bytes());
    payload.extend(0_u16.to_le_bytes());
    payload.extend(parameters.to_le_bytes());
    payload.extend([0, 0, 0]);
    socket.respond(&payload);
}

pub(super) fn column(socket: &TestSocket) {
    let mut payload = Vec::new();
    for text in ["def", "", "", "", "v", ""] {
        payload.push(u8::try_from(text.len()).unwrap());
        payload.extend(text.as_bytes());
    }
    payload.push(0x0c);
    payload.extend(45_u16.to_le_bytes());
    payload.extend(11_u32.to_le_bytes());
    payload.push(3); // MYSQL_TYPE_LONG
    payload.extend([0, 0, 0, 0, 0]);
    socket.respond(&payload);
}
