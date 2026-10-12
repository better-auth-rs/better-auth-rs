use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::text_command::CommandSql;

use bytes::{Buf, Bytes, BytesMut};

use crate::collation::{CharSet, Collation};
use crate::error::Error;
use crate::io::MySqlBufExt;
use crate::io::{ProtocolDecode, ProtocolEncode};
use crate::net::{BufferedSocket, Socket};
use crate::protocol::response::{EofPacket, ErrPacket, OkPacket, Status};
use crate::protocol::statement::PrepareOk;
use crate::protocol::{Capabilities, Packet};
use crate::{MySqlConnectOptions, MySqlDatabaseError};

pub struct MySqlStream<S = Box<dyn Socket>> {
    // Wrapping the socket in `Box` allows us to unsize in-place.
    pub(crate) socket: BufferedSocket<S>,
    pub(crate) server_version: (u16, u16, u16),
    pub(super) capabilities: Capabilities,
    pub(crate) sequence_id: u8,
    pub(crate) waiting: VecDeque<PendingResponse>,
    pub(super) packet_size: Option<usize>,
    pub(super) packet_buffer: BytesMut,
    pub(crate) charset: CharSet,
    pub(crate) collation: Collation,
    pub(crate) is_tls: bool,
}

#[derive(Debug)]
pub(crate) struct PendingResponse {
    pub(crate) state: Waiting,
    sql: Option<CommandSql>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waiting {
    // waiting for a result set
    Result,

    // waiting for a row within a result set
    Row,

    // None waits for PREPARE_OK; Some counts the remaining metadata packets.
    Prepare(Option<usize>),

    // Metadata must drain before an EOF can finish the row stream.
    ResultMetadata(usize),
}

impl<S: Socket> MySqlStream<S> {
    pub(crate) fn with_socket(
        charset: CharSet,
        collation: Collation,
        options: &MySqlConnectOptions,
        socket: S,
    ) -> Self {
        let mut capabilities = Capabilities::PROTOCOL_41
            | Capabilities::IGNORE_SPACE
            | Capabilities::DEPRECATE_EOF
            | Capabilities::FOUND_ROWS
            | Capabilities::TRANSACTIONS
            | Capabilities::SECURE_CONNECTION
            | Capabilities::PLUGIN_AUTH_LENENC_DATA
            | Capabilities::MULTI_STATEMENTS
            | Capabilities::MULTI_RESULTS
            | Capabilities::PLUGIN_AUTH
            | Capabilities::PS_MULTI_RESULTS
            | Capabilities::SSL;

        if options.database.is_some() {
            capabilities |= Capabilities::CONNECT_WITH_DB;
        }

        Self {
            waiting: VecDeque::new(),
            packet_size: None,
            packet_buffer: BytesMut::new(),
            capabilities,
            server_version: (0, 0, 0),
            sequence_id: 0,
            collation,
            charset,
            socket: BufferedSocket::new(socket),
            is_tls: false,
        }
    }

    pub(crate) async fn wait_until_ready(&mut self) -> Result<(), Error> {
        if !self.socket.write_buffer().is_empty() {
            self.socket.flush().await?;
        }

        while !self.waiting.is_empty() {
            while matches!(
                self.waiting.front().map(|pending| pending.state),
                Some(Waiting::Prepare(_) | Waiting::ResultMetadata(_))
            ) {
                self.recv_packet().await?;
            }
            while self.waiting.front().map(|pending| pending.state) == Some(Waiting::Row) {
                let packet = self.recv_packet().await?;

                if !packet.is_empty() && packet[0] == 0xfe && packet.len() < 9 {
                    let eof = packet.eof(self.capabilities)?;

                    if eof.status.contains(Status::SERVER_MORE_RESULTS_EXISTS) {
                        self.waiting.front_mut().unwrap().state = Waiting::Result;
                    } else {
                        self.waiting.pop_front();
                    };
                }
            }

            while self.waiting.front().map(|pending| pending.state) == Some(Waiting::Result) {
                let packet = self.recv_packet().await?;

                if !packet.is_empty() && (packet[0] == 0x00 || packet[0] == 0xff) {
                    let ok = packet.ok()?;

                    if !ok.status.contains(Status::SERVER_MORE_RESULTS_EXISTS) {
                        self.waiting.pop_front();
                    }
                } else {
                    self.skip_result_metadata(packet).await?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn write_command<'en, T>(
        &mut self,
        payload: T,
        sql: Option<&str>,
        state: Waiting,
    ) -> Result<(), Error>
    where
        T: ProtocolEncode<'en, Capabilities>,
    {
        self.write_command_with_sql(
            payload,
            sql.map(|sql| CommandSql::Utf8(Arc::from(sql))),
            state,
        )
    }

    fn write_command_with_sql<'en, T>(
        &mut self,
        payload: T,
        sql: Option<CommandSql>,
        state: Waiting,
    ) -> Result<(), Error>
    where
        T: ProtocolEncode<'en, Capabilities>,
    {
        self.sequence_id = 0;
        self.write_packet(payload)?;
        // Keep attribution with queued bytes when cancellation interrupts their flush or response.
        self.waiting.push_back(PendingResponse { state, sql });
        Ok(())
    }

    pub(crate) async fn send_command<'en, T>(
        &mut self,
        payload: T,
        sql: Option<&str>,
        state: Waiting,
    ) -> Result<(), Error>
    where
        T: ProtocolEncode<'en, Capabilities>,
    {
        self.write_command(payload, sql, state)?;
        self.flush().await?;
        Ok(())
    }

    pub(crate) async fn send_text_command(
        &mut self,
        command: &crate::MySqlTextCommand,
    ) -> Result<(), Error> {
        self.write_command_with_sql(
            crate::protocol::text::Query(command.sql()),
            Some(CommandSql::Text(command.clone())),
            Waiting::Result,
        )?;
        self.flush().await?;
        Ok(())
    }

    pub(crate) fn start_result_metadata(&mut self, columns: usize) {
        let eof = !self.capabilities.contains(Capabilities::DEPRECATE_EOF) && columns > 0;
        let remaining = columns + usize::from(eof);
        self.waiting.front_mut().unwrap().state = if remaining == 0 {
            Waiting::Row
        } else {
            Waiting::ResultMetadata(remaining)
        };
    }

    fn advance_metadata(&mut self, payload: &Bytes) -> Result<(), Error> {
        let Some(pending) = self.waiting.front_mut() else {
            return Ok(());
        };
        let remaining = match pending.state {
            Waiting::Prepare(None) => {
                let ok = PrepareOk::decode_with(payload.clone(), self.capabilities)?;
                let eof = !self.capabilities.contains(Capabilities::DEPRECATE_EOF);
                usize::from(ok.params)
                    + usize::from(ok.columns)
                    + usize::from(eof && ok.params > 0)
                    + usize::from(eof && ok.columns > 0)
            }
            Waiting::Prepare(Some(remaining)) => remaining - 1,
            Waiting::ResultMetadata(remaining) => {
                pending.state = if remaining == 1 {
                    Waiting::Row
                } else {
                    Waiting::ResultMetadata(remaining - 1)
                };
                return Ok(());
            }
            Waiting::Result | Waiting::Row => return Ok(()),
        };
        if remaining == 0 {
            self.waiting.pop_front();
        } else {
            pending.state = Waiting::Prepare(Some(remaining));
        }
        Ok(())
    }

    pub(crate) async fn send_packet<'en, T>(&mut self, payload: T) -> Result<(), Error>
    where
        T: ProtocolEncode<'en, Capabilities>,
    {
        self.sequence_id = 0;
        self.write_packet(payload)?;
        self.flush().await?;
        Ok(())
    }

    pub(crate) fn write_packet<'en, T>(&mut self, payload: T) -> Result<(), Error>
    where
        T: ProtocolEncode<'en, Capabilities>,
    {
        self.socket
            .write_with(Packet(payload), (self.capabilities, &mut self.sequence_id))
    }

    async fn recv_packet_part(&mut self) -> Result<Bytes, Error> {
        let packet_size = if let Some(packet_size) = self.packet_size {
            packet_size
        } else {
            let mut header: Bytes = self.socket.read(4).await?;
            // The three-byte length always fits usize on supported targets.
            #[allow(clippy::cast_possible_truncation)]
            let packet_size = header.get_uint_le(3) as usize;
            self.sequence_id = header.get_u8().wrapping_add(1);
            // A cancelled payload read must not consume a second header during drain.
            self.packet_size = Some(packet_size);
            packet_size
        };
        let payload = self.socket.read(packet_size).await?;
        self.packet_size = None;
        Ok(payload)
    }

    // receive the next packet from the database server
    // may block (async) on more data from the server
    pub(crate) async fn recv_packet(&mut self) -> Result<Packet<Bytes>, Error> {
        let payload = loop {
            let part = self.recv_packet_part().await?;
            let complete = part.len() < 0xFF_FF_FF;
            if complete && self.packet_buffer.is_empty() {
                break part;
            }
            // Keep completed fragments when cancellation interrupts the next fragment.
            self.packet_buffer.extend_from_slice(&part);
            if complete {
                break self.packet_buffer.split().freeze();
            }
        };

        if payload
            .first()
            .ok_or(err_protocol!("Packet empty"))?
            .eq(&0xff)
        {
            let sql = self.waiting.pop_front().and_then(|pending| pending.sql);

            // instead of letting this packet be looked at everywhere, we check here
            // and emit a proper Error
            return Err(MySqlDatabaseError(
                ErrPacket::decode_with(payload, self.capabilities)?,
                sql,
            )
            .into());
        }

        self.advance_metadata(&payload)?;
        Ok(Packet(payload))
    }

    pub(crate) async fn recv<'de, T>(&mut self) -> Result<T, Error>
    where
        T: ProtocolDecode<'de, Capabilities>,
    {
        self.recv_packet().await?.decode_with(self.capabilities)
    }

    pub(crate) async fn recv_ok(&mut self) -> Result<OkPacket, Error> {
        self.recv_packet().await?.ok()
    }

    pub(crate) async fn maybe_recv_eof(&mut self) -> Result<Option<EofPacket>, Error> {
        if self.capabilities.contains(Capabilities::DEPRECATE_EOF) {
            Ok(None)
        } else {
            self.recv().await.map(Some)
        }
    }

    async fn skip_result_metadata(&mut self, mut packet: Packet<Bytes>) -> Result<(), Error> {
        let num_columns: u64 = packet.get_uint_lenenc(); // column count
        let num_columns = usize::try_from(num_columns)
            .map_err(|_| err_protocol!("column count overflows usize: {num_columns}"))?;
        self.start_result_metadata(num_columns);

        for _ in 0..num_columns {
            let _ = self.recv_packet().await?;
        }

        self.maybe_recv_eof().await?;

        Ok(())
    }

    pub fn boxed_socket(self) -> MySqlStream {
        MySqlStream {
            socket: self.socket.boxed(),
            server_version: self.server_version,
            capabilities: self.capabilities,
            sequence_id: self.sequence_id,
            waiting: self.waiting,
            packet_size: self.packet_size,
            packet_buffer: self.packet_buffer,
            charset: self.charset,
            collation: self.collation,
            is_tls: self.is_tls,
        }
    }
}

impl<S> Deref for MySqlStream<S> {
    type Target = BufferedSocket<S>;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<S> DerefMut for MySqlStream<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

#[cfg(test)]
mod error_transport_tests;

#[cfg(test)]
mod error_transport_live_tests;

#[cfg(test)]
mod error_transport_support;

#[cfg(test)]
mod text_command_tests;
