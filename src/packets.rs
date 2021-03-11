// Copyright (c) 2017 Anatoly Ikorsky
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

use byteorder::{ByteOrder, LittleEndian as LE, ReadBytesExt, WriteBytesExt};
use lexical::parse;
use regex::bytes::Regex;
use saturating::Saturating as S;

use std::{
    borrow::Cow,
    cmp::{max, min},
    collections::HashMap,
    convert::TryFrom,
    fmt,
    io::{self, Read, Write},
    marker::PhantomData,
    ptr,
};

use crate::{
    constants::{
        CapabilityFlags, ColumnFlags, ColumnType, Command, SessionStateType, StatusFlags,
        MAX_PAYLOAD_LEN, UTF8MB4_GENERAL_CI, UTF8_GENERAL_CI,
    },
    io::{ReadMysqlExt, WriteMysqlExt},
    misc::{lenenc_str_len, LimitRead, LimitWrite, RawText},
    value::{ClientSide, SerializationSide, Value},
};

lazy_static::lazy_static! {
    static ref MARIADB_VERSION_RE: Regex =
        { Regex::new(r"^5.5.5-(\d{1,2})\.(\d{1,2})\.(\d{1,3})-MariaDB").unwrap() };
    static ref VERSION_RE: Regex = { Regex::new(r"^(\d{1,2})\.(\d{1,2})\.(\d{1,3})(.*)").unwrap() };
}

/// Represents MySql Column (column packet).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Column<'a> {
    schema: Cow<'a, [u8]>,
    table: Cow<'a, [u8]>,
    org_table: Cow<'a, [u8]>,
    name: Cow<'a, [u8]>,
    org_name: Cow<'a, [u8]>,
    column_length: u32,
    character_set: u16,
    flags: ColumnFlags,
    column_type: ColumnType,
    decimals: u8,
}

impl<'a> Column<'a> {
    pub fn new(column_type: ColumnType) -> Self {
        Self {
            schema: Default::default(),
            table: Default::default(),
            org_table: Default::default(),
            name: Default::default(),
            org_name: Default::default(),
            column_length: Default::default(),
            character_set: Default::default(),
            flags: ColumnFlags::empty(),
            column_type,
            decimals: Default::default(),
        }
    }

    pub fn into_owned(self) -> Column<'static> {
        Column {
            schema: self.schema.into_owned().into(),
            table: self.table.into_owned().into(),
            org_table: self.org_table.into_owned().into(),
            name: self.name.into_owned().into(),
            org_name: self.org_name.into_owned().into(),
            column_length: self.column_length,
            character_set: self.character_set,
            flags: self.flags,
            column_type: self.column_type,
            decimals: self.decimals,
        }
    }

    pub fn with_schema(mut self, schema: impl Into<Cow<'a, [u8]>>) -> Self {
        self.schema = schema.into();
        self
    }

    pub fn with_table(mut self, table: impl Into<Cow<'a, [u8]>>) -> Self {
        self.table = table.into();
        self
    }

    pub fn with_org_table(mut self, org_table: impl Into<Cow<'a, [u8]>>) -> Self {
        self.org_table = org_table.into();
        self
    }

    pub fn with_name(mut self, name: impl Into<Cow<'a, [u8]>>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_org_name(mut self, org_name: impl Into<Cow<'a, [u8]>>) -> Self {
        self.org_name = org_name.into();
        self
    }

    pub fn with_flags(mut self, flags: ColumnFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_column_length(mut self, column_length: u32) -> Self {
        self.column_length = column_length;
        self
    }

    pub fn with_character_set(mut self, character_set: u16) -> Self {
        self.character_set = character_set;
        self
    }

    pub fn with_decimals(mut self, decimals: u8) -> Self {
        self.decimals = decimals;
        self
    }

    pub fn read<T: io::Read>(mut input: T) -> io::Result<Column<'static>> {
        input.read_lenenc_str()?; // "def"
        let schema = input.read_lenenc_str()?;
        let table = input.read_lenenc_str()?;
        let org_table = input.read_lenenc_str()?;
        let name = input.read_lenenc_str()?;
        let org_name = input.read_lenenc_str()?;
        input.read_u8()?; // 0x0c
        let character_set = input.read_u16::<LE>()?;
        let column_length = input.read_u32::<LE>()?;
        let column_type = input.read_u8()?;
        let flags = input.read_u16::<LE>()?;
        let decimals = input.read_u8()?;
        input.read_u16::<LE>()?; // [0x00, 0x00]

        Ok(Column {
            schema: schema.into(),
            table: table.into(),
            org_table: org_table.into(),
            name: name.into(),
            org_name: org_name.into(),
            column_length,
            character_set,
            flags: ColumnFlags::from_bits(flags).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid column flags")
            })?,
            column_type: ColumnType::try_from(column_type)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid column type"))?,
            decimals,
        })
    }

    /// Returns value of the column_length field of a column packet.
    pub fn column_length(&self) -> u32 {
        self.column_length
    }

    /// Returns value of the column_type field of a column packet.
    pub fn column_type(&self) -> ColumnType {
        self.column_type
    }

    /// Returns value of the character_set field of a column packet.
    pub fn character_set(&self) -> u16 {
        self.character_set
    }

    /// Returns value of the flags field of a column packet.
    pub fn flags(&self) -> ColumnFlags {
        self.flags
    }

    /// Returns value of the decimals field of a column packet.
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Returns value of the schema field of a column packet as a byte slice.
    pub fn schema_ref(&self) -> &[u8] {
        self.schema.as_ref()
    }

    /// Returns value of the schema field of a column packet as a string (lossy converted).
    pub fn schema_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.schema_ref())
    }

    /// Returns value of the table field of a column packet as a byte slice.
    pub fn table_ref(&self) -> &[u8] {
        self.table.as_ref()
    }

    /// Returns value of the table field of a column packet as a string (lossy converted).
    pub fn table_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.table_ref())
    }

    /// Returns value of the org_table field of a column packet as a byte slice.
    ///
    /// "org_table" is for original table name.
    pub fn org_table_ref(&self) -> &[u8] {
        self.org_table.as_ref()
    }

    /// Returns value of the org_table field of a column packet as a string (lossy converted).
    pub fn org_table_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.org_table_ref())
    }

    /// Returns value of the name field of a column packet as a byte slice.
    pub fn name_ref(&self) -> &[u8] {
        self.name.as_ref()
    }

    /// Returns value of the name field of a column packet as a string (lossy converted).
    pub fn name_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.name_ref())
    }

    /// Returns value of the org_name field of a column packet as a byte slice.
    ///
    /// "org_name" is for original column name.
    pub fn org_name_ref(&self) -> &[u8] {
        self.org_name.as_ref()
    }

    /// Returns value of the org_name field of a column packet as a string (lossy converted).
    pub fn org_name_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.org_name_ref())
    }
}

/// Represents parsed change in session state (part of MySql's Ok packet).
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SessionStateChange<'a> {
    IsTracked(bool),
    Schema(Cow<'a, [u8]>),
    SystemVariable(Cow<'a, [u8]>, Cow<'a, [u8]>),
    UnknownLayout(Cow<'a, [u8]>),
}

impl<'a> SessionStateChange<'a> {
    pub fn into_owned(self) -> SessionStateChange<'static> {
        match self {
            SessionStateChange::SystemVariable(name, value) => SessionStateChange::SystemVariable(
                name.into_owned().into(),
                value.into_owned().into(),
            ),
            SessionStateChange::Schema(schema) => {
                SessionStateChange::Schema(schema.into_owned().into())
            }
            SessionStateChange::IsTracked(x) => SessionStateChange::IsTracked(x),
            SessionStateChange::UnknownLayout(data) => {
                SessionStateChange::UnknownLayout(data.into_owned().into())
            }
        }
    }
}

/// Represents change in session state (part of MySql's Ok packet).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionStateInfo<'a> {
    data_type: SessionStateType,
    data: Cow<'a, [u8]>,
}

impl<'a> SessionStateInfo<'a> {
    pub fn parse(mut payload: &[u8]) -> io::Result<SessionStateInfo<'_>> {
        let data_type = payload.read_u8()?;
        Ok(SessionStateInfo {
            data_type: data_type.into(),
            data: read_lenenc_str!(&mut payload)?.into(),
        })
    }

    pub fn into_owned(self) -> SessionStateInfo<'static> {
        let SessionStateInfo { data_type, data } = self;
        SessionStateInfo {
            data_type,
            data: data.into_owned().into(),
        }
    }

    pub fn data_type(&self) -> SessionStateType {
        self.data_type
    }

    pub fn decode(&self) -> io::Result<SessionStateChange<'_>> {
        let mut reader = self.data.as_ref();
        match self.data_type {
            SessionStateType::SESSION_TRACK_SYSTEM_VARIABLES => {
                let name = read_lenenc_str!(&mut reader)?;
                let value = read_lenenc_str!(&mut reader)?;
                Ok(SessionStateChange::SystemVariable(
                    name.into(),
                    value.into(),
                ))
            }
            SessionStateType::SESSION_TRACK_SCHEMA => {
                let schema = read_lenenc_str!(&mut reader)?;
                Ok(SessionStateChange::Schema(schema.into()))
            }
            SessionStateType::SESSION_TRACK_STATE_CHANGE => {
                let is_tracked = read_lenenc_str!(&mut reader)?;
                Ok(SessionStateChange::IsTracked(is_tracked == b"1"))
            }
            // Layout not specified in documentation
            SessionStateType::SESSION_TRACK_GTIDS
            | SessionStateType::SESSION_TRACK_TRANSACTION_CHARACTERISTICS
            | SessionStateType::SESSION_TRACK_TRANSACTION_STATE => {
                Ok(SessionStateChange::UnknownLayout(self.data.clone()))
            }
        }
    }
}

/// OK packet kind (see _OK packet identifier_ section of [WL#7766][1]).
///
/// [1]: https://dev.mysql.com/worklog/task/?id=7766
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum OkPacketKind {
    /// This packet terminates a result set (text or binary).
    ResultSetTerminator,
    /// This packet terminates a binlog network stream.
    NetworkStreamTerminator,
    /// Ok packet that is not a result set terminator.
    Other,
}

/// Represents MySql's Ok packet.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OkPacket<'a> {
    affected_rows: u64,
    last_insert_id: Option<u64>,
    status_flags: StatusFlags,
    warnings: u16,
    info: Option<Cow<'a, [u8]>>,
    session_state_info: Option<SessionStateInfo<'a>>,
}

/// Parses Ok packet from `payload` assuming passed client-server `capabilities`.
pub fn parse_ok_packet(
    payload: &[u8],
    capabilities: CapabilityFlags,
    kind: OkPacketKind,
) -> io::Result<OkPacket<'_>> {
    OkPacket::parse(payload, capabilities, kind)
}

impl<'a> OkPacket<'a> {
    /// Parses Ok packet from `payload` assuming passed client-server `capabilities`.
    fn parse(
        mut payload: &[u8],
        capabilities: CapabilityFlags,
        kind: OkPacketKind,
    ) -> io::Result<OkPacket> {
        let header = payload.read_u8()?;
        let (affected_rows, last_insert_id, status_flags, warnings, info, session_state_info) =
            if kind == OkPacketKind::Other && header == 0x00 {
                let affected_rows = payload.read_lenenc_int()?;
                let last_insert_id = payload.read_lenenc_int()?;
                // We assume that CLIENT_PROTOCOL_41 was set
                let status_flags = StatusFlags::from_bits_truncate(payload.read_u16::<LE>()?);
                let warnings = payload.read_u16::<LE>()?;

                let (info, session_state_info) =
                    if capabilities.contains(CapabilityFlags::CLIENT_SESSION_TRACK) {
                        let info = read_lenenc_str!(&mut payload)?;
                        let session_state_info =
                            if status_flags.contains(StatusFlags::SERVER_SESSION_STATE_CHANGED) {
                                read_lenenc_str!(&mut payload)?
                            } else {
                                &[][..]
                            };
                        (info, session_state_info)
                    } else {
                        (payload, &[][..])
                    };
                (
                    affected_rows,
                    last_insert_id,
                    status_flags,
                    warnings,
                    info,
                    session_state_info,
                )
            } else if (kind == OkPacketKind::ResultSetTerminator
                || kind == OkPacketKind::NetworkStreamTerminator)
                && header == 0xFE
                && payload.len() < 8
            {
                // We assume that CLIENT_PROTOCOL_41 was set
                let warnings = payload.read_u16::<LE>()?;
                let status_flags = StatusFlags::from_bits_truncate(payload.read_u16::<LE>()?);
                (0, 0, status_flags, warnings, &[][..], &[][..])
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid OK_Packet header or length",
                ));
            };

        Ok(OkPacket {
            affected_rows,
            last_insert_id: if last_insert_id == 0 {
                None
            } else {
                Some(last_insert_id)
            },
            status_flags,
            warnings,
            info: if !info.is_empty() {
                Some(info.into())
            } else {
                None
            },
            session_state_info: if !session_state_info.is_empty() {
                Some(SessionStateInfo::parse(session_state_info)?)
            } else {
                None
            },
        })
    }

    pub fn into_owned(self) -> OkPacket<'static> {
        let OkPacket {
            affected_rows,
            last_insert_id,
            status_flags,
            warnings,
            info,
            session_state_info,
        } = self;
        OkPacket {
            affected_rows,
            last_insert_id,
            status_flags,
            warnings,
            info: info.map(|x| x.into_owned().into()),
            session_state_info: session_state_info.map(SessionStateInfo::into_owned),
        }
    }

    /// Value of the affected_rows field of an Ok packet.
    pub fn affected_rows(&self) -> u64 {
        self.affected_rows
    }

    /// Value of the last_insert_id field of an Ok packet.
    pub fn last_insert_id(&self) -> Option<u64> {
        self.last_insert_id
    }

    /// Value of the status_flags field of an Ok packet.
    pub fn status_flags(&self) -> StatusFlags {
        self.status_flags
    }

    /// Value of the warnings field of an Ok packet.
    pub fn warnings(&self) -> u16 {
        self.warnings
    }

    /// Value of the info field of an Ok packet as a byte slice.
    pub fn info_ref(&self) -> Option<&[u8]> {
        self.info.as_ref().map(|x| x.as_ref())
    }

    /// Value of the info field of an Ok packet as a string (lossy converted).
    pub fn info_str(&self) -> Option<Cow<str>> {
        self.info
            .as_ref()
            .map(|x| String::from_utf8_lossy(x.as_ref()))
    }

    pub fn session_state_info(&self) -> Option<&SessionStateInfo<'_>> {
        self.session_state_info.as_ref()
    }
}

/// Progress report information (may be in an error packet of MariaDB server).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProgressReport<'a> {
    stage: u8,
    max_stage: u8,
    progress: u32,
    stage_info: Cow<'a, [u8]>,
}

impl<'a> ProgressReport<'a> {
    fn new(stage: u8, max_stage: u8, progress: u32, stage_info: &[u8]) -> ProgressReport {
        ProgressReport {
            stage,
            max_stage,
            progress,
            stage_info: stage_info.into(),
        }
    }

    /// 1 to max_stage
    pub fn stage(&self) -> u8 {
        self.stage
    }

    pub fn max_stage(&self) -> u8 {
        self.max_stage
    }

    /// Progress as '% * 1000'
    pub fn progress(&self) -> u32 {
        self.progress
    }

    /// Status or state name as a byte slice.
    pub fn stage_info_ref(&self) -> &[u8] {
        &self.stage_info.as_ref()
    }

    /// Status or state name as a string (lossy converted).
    pub fn stage_info_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.stage_info.as_ref())
    }

    pub fn into_owned(self) -> ProgressReport<'static> {
        let ProgressReport {
            stage,
            max_stage,
            progress,
            stage_info,
        } = self;
        ProgressReport {
            stage,
            max_stage,
            progress,
            stage_info: stage_info.into_owned().into(),
        }
    }
}

impl<'a> fmt::Display for ProgressReport<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Stage: {} of {} '{}'  {:.2}% of stage done",
            self.stage(),
            self.max_stage(),
            self.progress(),
            self.stage_info_str()
        )
    }
}

/// MySql error packet.
///
/// May hold an error or a progress report.
#[derive(Debug, Clone, PartialEq)]
pub enum ErrPacket<'a> {
    /// (<error code>, <sql state>, <error message>)
    Error(u16, [u8; 5], Cow<'a, [u8]>),
    Progress(ProgressReport<'a>),
}

/// Parses error packet from `payload` assuming passed client-server `capabilities`.
pub fn parse_err_packet(
    payload: &[u8],
    capabilities: CapabilityFlags,
) -> io::Result<ErrPacket<'_>> {
    ErrPacket::parse(payload, capabilities)
}

impl<'a> ErrPacket<'a> {
    /// Parses error packet from `payload` assuming passed client-server `capabilities`.
    fn parse(mut payload: &[u8], capabilities: CapabilityFlags) -> io::Result<ErrPacket<'_>> {
        if payload.read_u8()? != 0xFF {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid ERR_Packet header",
            ));
        }

        let code = payload.read_u16::<LE>()?;
        // We assume that CLIENT_PROTOCOL_41 was set
        if code == 0xFFFF && capabilities.contains(CapabilityFlags::CLIENT_PROGRESS_OBSOLETE) {
            payload.read_u8()?; // Ignore number of strings.
            let stage = payload.read_u8()?;
            let max_stage = payload.read_u8()?;
            let progress = payload.read_uint::<LE>(3)?;
            let progress_info = read_lenenc_str!(&mut payload)?;
            Ok(ErrPacket::Progress(ProgressReport::new(
                stage,
                max_stage,
                progress as u32,
                progress_info,
            )))
        } else {
            match payload.get(0) {
                Some(b'#') => {
                    let (state, msg) =
                        split_at_or_err!(payload, 6, "EOF while reading error state")?;
                    Ok(ErrPacket::Error(
                        code,
                        unsafe { ptr::read(state.as_ptr().offset(1) as *const [u8; 5]) },
                        msg.into(),
                    ))
                }
                _ => Ok(ErrPacket::Error(
                    code,
                    [b'H', b'Y', b'0', b'0', b'0'],
                    payload.into(),
                )),
            }
        }
    }

    /// Returns false if this error packet contains progress report.
    pub fn is_error(&self) -> bool {
        match *self {
            ErrPacket::Error(..) => true,
            _ => false,
        }
    }

    /// Returns true if this error packet contains progress report.
    pub fn is_progress_report(&self) -> bool {
        !self.is_error()
    }

    /// Will panic if ErrPacket does not contains progress report
    pub fn progress_report(&self) -> &ProgressReport<'_> {
        match *self {
            ErrPacket::Progress(ref progress_report) => progress_report,
            _ => panic!("This ErrPacket does not contains progress report"),
        }
    }

    /// Will panic if ErrPacket contains progress report
    pub fn error_code(&self) -> u16 {
        match *self {
            ErrPacket::Error(code, ..) => code,
            _ => panic!("This ErrPacket contains progress report"),
        }
    }

    /// Will panic if ErrPacket contains progress report
    pub fn sql_state_ref(&self) -> &[u8; 5] {
        match *self {
            ErrPacket::Error(_, ref state, _) => state,
            _ => panic!("This ErrPacket contains progress report"),
        }
    }

    /// Will panic if ErrPacket contains progress report
    pub fn sql_state_str(&self) -> Cow<'_, str> {
        match *self {
            ErrPacket::Error(_, ref state, _) => String::from_utf8_lossy(&state[..]),
            _ => panic!("This ErrPacket contains progress report"),
        }
    }

    /// Will panic if ErrPacket contains progress report
    pub fn message_ref(&self) -> &[u8] {
        match *self {
            ErrPacket::Error(_, _, ref message) => message.as_ref(),
            _ => panic!("This ErrPacket contains progress report"),
        }
    }

    /// Will panic if ErrPacket contains progress report
    pub fn message_str(&self) -> Cow<'_, str> {
        match *self {
            ErrPacket::Error(_, _, ref message) => String::from_utf8_lossy(message.as_ref()),
            _ => panic!("This ErrPacket contains progress report"),
        }
    }

    pub fn into_owned(self) -> ErrPacket<'static> {
        match self {
            ErrPacket::Error(code, state, message) => {
                ErrPacket::Error(code, state, message.into_owned().into())
            }
            ErrPacket::Progress(progress_report) => {
                ErrPacket::Progress(progress_report.into_owned())
            }
        }
    }
}

impl<'a> fmt::Display for ErrPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrPacket::Error(..) => write!(
                f,
                "ERROR {} ({}): {}",
                self.error_code(),
                self.sql_state_str(),
                self.message_str()
            ),
            ErrPacket::Progress(ref progress_report) => write!(f, "{}", progress_report),
        }
    }
}

/// Represents MySql's local infile packet.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LocalInfilePacket<'a> {
    file_name: Cow<'a, [u8]>,
}

/// Will parse payload as a local infile packet.
pub fn parse_local_infile_packet(payload: &[u8]) -> io::Result<LocalInfilePacket<'_>> {
    LocalInfilePacket::parse(payload)
}

impl<'a> LocalInfilePacket<'a> {
    /// Will parse payload as a local infile packet.
    fn parse(mut payload: &[u8]) -> io::Result<LocalInfilePacket<'_>> {
        if payload.read_u8()? != 0xfb {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid LOCAL_INFILE packet header",
            ));
        }

        Ok(LocalInfilePacket {
            file_name: payload.into(),
        })
    }

    /// Value of the file_name field of a local infile packet as a byte slice.
    pub fn file_name_ref(&self) -> &[u8] {
        self.file_name.as_ref()
    }

    /// Value of the file_name field of a local infile packet as a string (lossy converted).
    pub fn file_name_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.file_name.as_ref())
    }

    pub fn into_owned(self) -> LocalInfilePacket<'static> {
        LocalInfilePacket {
            file_name: self.file_name.into_owned().into(),
        }
    }
}

const MYSQL_NATIVE_PASSWORD_PLUGIN_NAME: &[u8] = b"mysql_native_password";
const CACHING_SHA2_PASSWORD_PLUGIN_NAME: &[u8] = b"caching_sha2_password";

/// Authentication plugin
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum AuthPlugin<'a> {
    /// Legacy authentication plugin
    MysqlNativePassword,
    /// Default since MySql v8.0.4
    CachingSha2Password,
    Other(Cow<'a, [u8]>),
}

impl<'a> AuthPlugin<'a> {
    pub fn from_bytes(name: &'a [u8]) -> AuthPlugin<'a> {
        match name {
            CACHING_SHA2_PASSWORD_PLUGIN_NAME => AuthPlugin::CachingSha2Password,
            MYSQL_NATIVE_PASSWORD_PLUGIN_NAME => AuthPlugin::MysqlNativePassword,
            name => AuthPlugin::Other(name.into()),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            AuthPlugin::MysqlNativePassword => MYSQL_NATIVE_PASSWORD_PLUGIN_NAME,
            AuthPlugin::CachingSha2Password => CACHING_SHA2_PASSWORD_PLUGIN_NAME,
            AuthPlugin::Other(name) => &*name,
        }
    }

    pub fn into_owned(self) -> AuthPlugin<'static> {
        match self {
            AuthPlugin::CachingSha2Password => AuthPlugin::CachingSha2Password,
            AuthPlugin::MysqlNativePassword => AuthPlugin::MysqlNativePassword,
            AuthPlugin::Other(name) => AuthPlugin::Other(name.into_owned().into()),
        }
    }

    /// Generates auth plugin data for this plugin.
    ///
    /// It'll generate `None` if password is `None` or empty.
    pub fn gen_data(&self, pass: Option<&str>, nonce: &[u8]) -> Option<Vec<u8>> {
        use super::scramble::{scramble_native, scramble_sha256};

        match pass {
            Some(pass) => match self {
                AuthPlugin::CachingSha2Password => {
                    scramble_sha256(nonce, pass.as_bytes()).map(|x| Vec::from(&x[..]))
                }
                AuthPlugin::MysqlNativePassword => {
                    scramble_native(nonce, pass.as_bytes()).map(|x| Vec::from(&x[..]))
                }
                AuthPlugin::Other(_) => None,
            },
            None => None,
        }
    }
}

/// Extra auth-data beyond the initial challenge.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthMoreData<'a> {
    data: Cow<'a, [u8]>,
}

impl<'a> AuthMoreData<'a> {
    fn parse(mut payload: &'a [u8]) -> io::Result<Self> {
        match payload.read_u8()? {
            0x01 => Ok(AuthMoreData {
                data: payload.into(),
            }),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid AuthMoreData header",
            )),
        }
    }

    pub fn data(&self) -> &[u8] {
        &*self.data
    }

    pub fn into_owned(self) -> AuthMoreData<'static> {
        AuthMoreData {
            data: self.data.into_owned().into(),
        }
    }
}

/// Parses payload as an auth more data packet.
pub fn parse_auth_more_data(payload: &[u8]) -> io::Result<AuthMoreData<'_>> {
    AuthMoreData::parse(payload)
}

/// Authentication Method Switch Request Packet.
///
/// If both server and client support `CLIENT_PLUGIN_AUTH` capability, server can send this packet
/// to ask client to use another authentication method.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthSwitchRequest<'a> {
    auth_plugin: AuthPlugin<'a>,
    plugin_data: Cow<'a, [u8]>,
}

impl<'a> AuthSwitchRequest<'a> {
    fn parse(mut payload: &'a [u8]) -> io::Result<Self> {
        match payload.read_u8()? {
            0xfe => {
                let mut null_offset = 0;
                for byte in payload.iter() {
                    if *byte == 0x00 {
                        break;
                    }
                    null_offset += 1;
                }
                let (auth_plugin, mut payload) =
                    split_at_or_err!(payload, null_offset, "Invalid AuthSwitchRequest packet")?;
                payload.read_u8()?;
                let plugin_data = if payload[payload.len() - 1] == 0 {
                    &payload[..payload.len() - 1]
                } else {
                    payload
                };
                Ok(Self {
                    auth_plugin: AuthPlugin::from_bytes(auth_plugin),
                    plugin_data: plugin_data.into(),
                })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid AuthSwitchRequest header",
            )),
        }
    }

    pub fn auth_plugin(&self) -> &AuthPlugin<'_> {
        &self.auth_plugin
    }

    pub fn plugin_data(&self) -> &[u8] {
        &*self.plugin_data
    }

    pub fn into_owned(self) -> AuthSwitchRequest<'static> {
        AuthSwitchRequest {
            auth_plugin: self.auth_plugin.into_owned(),
            plugin_data: self.plugin_data.into_owned().into(),
        }
    }
}

/// Parses payload as an auth switch request packet.
pub fn parse_auth_switch_request(payload: &[u8]) -> io::Result<AuthSwitchRequest<'_>> {
    AuthSwitchRequest::parse(payload)
}

/// Represents MySql's initial handshake packet.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HandshakePacket<'a> {
    protocol_version: u8,
    server_version: Cow<'a, [u8]>,
    connection_id: u32,
    scramble_1: Cow<'a, [u8]>,
    scramble_2: Option<Cow<'a, [u8]>>,
    capabilities: CapabilityFlags,
    default_collation: u8,
    status_flags: StatusFlags,
    auth_plugin: Option<AuthPlugin<'a>>,
}

/// Parses payload as an initial handshake packet.
pub fn parse_handshake_packet(payload: &[u8]) -> io::Result<HandshakePacket<'_>> {
    HandshakePacket::parse(payload)
}

impl<'a> HandshakePacket<'a> {
    /// Parses payload as an initial handshake packet.
    fn parse(mut payload: &[u8]) -> io::Result<HandshakePacket<'_>> {
        let protocol_version = payload.read_u8()?;
        let mut nul_byte_pos = 0;
        for (i, byte) in payload.iter().enumerate() {
            if *byte == 0x00 {
                nul_byte_pos = i;
                break;
            }
        }
        let (server_version, mut payload) =
            split_at_or_err!(payload, nul_byte_pos, "Invalid handshake packet")?;
        payload.read_u8()?;
        let connection_id = payload.read_u32::<LE>()?;
        let (scramble_1, mut payload) = split_at_or_err!(payload, 8, "Invalid handshake packet")?;
        payload.read_u8()?;
        let capabilities_1 = payload.read_u16::<LE>()?;
        let default_collation = payload.read_u8()?;
        let status_flags = payload.read_u16::<LE>()?;
        let capabilities_2 = payload.read_u16::<LE>()?;
        let capabilities = CapabilityFlags::from_bits_truncate(
            u32::from(capabilities_1) | (u32::from(capabilities_2) << 16),
        );
        let scramble_len = payload.read_u8()?;
        let (_, payload) = split_at_or_err!(payload, 10, "Invalid handshake packet")?;
        let (scramble_2, payload) =
            if capabilities.contains(CapabilityFlags::CLIENT_SECURE_CONNECTION) {
                let (scramble_2, mut payload) = split_at_or_err!(
                    payload,
                    max(12, scramble_len as i8 - 9) as usize,
                    "Invalid handshake packet"
                )?;
                payload.read_u8()?;
                (Some(scramble_2), payload)
            } else {
                (None, payload)
            };
        let auth_plugin_name = if capabilities.contains(CapabilityFlags::CLIENT_PLUGIN_AUTH) {
            if let Some(pos) = payload.iter().position(|&x| x == 0x00) {
                Some(&payload[..pos])
            } else {
                Some(payload)
            }
        } else {
            None
        };
        Ok(HandshakePacket {
            protocol_version,
            server_version: server_version.into(),
            connection_id,
            scramble_1: scramble_1.into(),
            scramble_2: scramble_2.map(Into::into),
            capabilities,
            default_collation,
            status_flags: StatusFlags::from_bits_truncate(status_flags),
            auth_plugin: auth_plugin_name.map(AuthPlugin::from_bytes),
        })
    }

    pub fn into_owned(self) -> HandshakePacket<'static> {
        HandshakePacket {
            protocol_version: self.protocol_version,
            server_version: self.server_version.into_owned().into(),
            connection_id: self.connection_id,
            scramble_1: self.scramble_1.into_owned().into(),
            scramble_2: self.scramble_2.map(Cow::into_owned).map(Into::into),
            capabilities: self.capabilities,
            default_collation: self.default_collation,
            status_flags: self.status_flags,
            auth_plugin: self.auth_plugin.map(AuthPlugin::into_owned),
        }
    }

    /// Value of the protocol_version field of an initial handshake packet.
    pub fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    /// Value of the server_version field of an initial handshake packet as a byte slice.
    pub fn server_version_ref(&self) -> &[u8] {
        self.server_version.as_ref()
    }

    /// Value of the server_version field of an initial handshake packet as a string
    /// (lossy converted).
    pub fn server_version_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.server_version_ref())
    }

    /// Parsed server version.
    ///
    /// Will parse first \d+.\d+.\d+ of a server version string (if any).
    pub fn server_version_parsed(&self) -> Option<(u16, u16, u16)> {
        VERSION_RE
            .captures(self.server_version_ref())
            .map(|captures| {
                // Should not panic because validated with regex
                (
                    parse::<u16, _>(captures.get(1).unwrap().as_bytes()).unwrap(),
                    parse::<u16, _>(captures.get(2).unwrap().as_bytes()).unwrap(),
                    parse::<u16, _>(captures.get(3).unwrap().as_bytes()).unwrap(),
                )
            })
    }

    /// Parsed mariadb server version.
    pub fn maria_db_server_version_parsed(&self) -> Option<(u16, u16, u16)> {
        MARIADB_VERSION_RE
            .captures(self.server_version_ref())
            .map(|captures| {
                // Should not panic because validated with regex
                (
                    parse::<u16, _>(captures.get(1).unwrap().as_bytes()).unwrap(),
                    parse::<u16, _>(captures.get(2).unwrap().as_bytes()).unwrap(),
                    parse::<u16, _>(captures.get(3).unwrap().as_bytes()).unwrap(),
                )
            })
    }

    /// Value of the connection_id field of an initial handshake packet.
    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    /// Value of the scramble_1 field of an initial handshake packet as a byte slice.
    pub fn scramble_1_ref(&self) -> &[u8] {
        self.scramble_1.as_ref()
    }

    /// Value of the scramble_2 field of an initial handshake packet as a byte slice.
    pub fn scramble_2_ref(&self) -> Option<&[u8]> {
        self.scramble_2.as_ref().map(Cow::as_ref)
    }

    /// Returns concatenated auth plugin nonce.
    pub fn nonce(&self) -> Vec<u8> {
        let mut out = Vec::from(self.scramble_1_ref());
        out.extend_from_slice(self.scramble_2_ref().unwrap_or(&[][..]));
        out
    }

    /// Value of a server capabilities.
    pub fn capabilities(&self) -> CapabilityFlags {
        self.capabilities
    }

    /// Value of the default_collation field of an initial handshake packet.
    pub fn default_collation(&self) -> u8 {
        self.default_collation
    }

    /// Value of a status flags.
    pub fn status_flags(&self) -> StatusFlags {
        self.status_flags
    }

    /// Value of the auth_plugin_name field of an initial handshake packet as a byte slice.
    pub fn auth_plugin_name_ref(&self) -> Option<&[u8]> {
        self.auth_plugin.as_ref().map(AuthPlugin::as_bytes)
    }

    /// Value of the auth_plugin_name field of an initial handshake packet as a string
    /// (lossy converted).
    pub fn auth_plugin_name_str(&self) -> Option<Cow<'_, str>> {
        self.auth_plugin
            .as_ref()
            .map(AuthPlugin::as_bytes)
            .map(String::from_utf8_lossy)
    }

    /// Auth plugin of a handshake packet
    pub fn auth_plugin(&self) -> Option<&AuthPlugin<'_>> {
        self.auth_plugin.as_ref()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HandshakeResponse {
    data: Vec<u8>,
}

impl HandshakeResponse {
    pub fn new(
        scramble_buf: &Option<impl AsRef<[u8]>>,
        server_version: (u16, u16, u16),
        user: Option<&str>,
        db_name: Option<&str>,
        auth_plugin: &AuthPlugin<'_>,
        client_flags: CapabilityFlags,
        connect_attributes: &HashMap<String, String>,
    ) -> HandshakeResponse {
        let scramble = scramble_buf.as_ref().map(|x| x.as_ref()).unwrap_or(&[]);
        let database = db_name.unwrap_or("");

        let collation = if server_version >= (5, 5, 3) {
            UTF8MB4_GENERAL_CI
        } else {
            UTF8_GENERAL_CI
        };

        let mut data = Vec::with_capacity(1024);
        data.write_u32::<LE>(client_flags.bits()).unwrap();
        data.resize(data.len() + 4, 0);
        data.push(collation as u8);
        data.resize(data.len() + 23, 0);
        data.extend_from_slice(user.unwrap_or("").as_bytes());
        data.push(0);
        data.push(scramble.len() as u8);
        data.extend_from_slice(scramble);
        data.extend_from_slice(database.as_bytes());
        data.push(0);
        if client_flags.contains(CapabilityFlags::CLIENT_PLUGIN_AUTH) {
            data.extend_from_slice(auth_plugin.as_bytes());
            data.push(0);
        }
        if client_flags.contains(CapabilityFlags::CLIENT_CONNECT_ATTRS) {
            let len = connect_attributes
                .iter()
                .map(|(k, v)| lenenc_str_len(k) + lenenc_str_len(v))
                .sum::<usize>();
            data.write_lenenc_int(len as u64).expect("out of memory");

            for (name, value) in connect_attributes {
                data.write_lenenc_str(name.as_bytes())
                    .expect("out of memory");
                data.write_lenenc_str(value.as_bytes())
                    .expect("out of memory");
            }
        }

        HandshakeResponse { data }
    }
}

impl AsRef<[u8]> for HandshakeResponse {
    fn as_ref(&self) -> &[u8] {
        &self.data[..]
    }
}

impl Into<Vec<u8>> for HandshakeResponse {
    fn into(self) -> Vec<u8> {
        self.data
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SslRequest {
    data: Vec<u8>,
}

impl SslRequest {
    pub fn new(capabilities: CapabilityFlags) -> SslRequest {
        let mut data = vec![0u8; 4 + 4 + 1 + 23];
        LE::write_u32(&mut data[0..], capabilities.bits());
        LE::write_u32(&mut data[4..], 1024 * 1024);
        data[8] = UTF8_GENERAL_CI as u8;
        SslRequest { data }
    }
}

impl AsRef<[u8]> for SslRequest {
    fn as_ref(&self) -> &[u8] {
        &self.data[..]
    }
}

impl Into<Vec<u8>> for SslRequest {
    fn into(self) -> Vec<u8> {
        self.data
    }
}

/// Represents MySql's statement packet.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct StmtPacket {
    statement_id: u32,
    num_columns: u16,
    num_params: u16,
    warning_count: u16,
}

/// Parses payload as a statement packet.
pub fn parse_stmt_packet(payload: &[u8]) -> io::Result<StmtPacket> {
    StmtPacket::parse(payload)
}

impl StmtPacket {
    /// Parses payload as a statement packet.
    fn parse(mut payload: &[u8]) -> io::Result<StmtPacket> {
        if payload.read_u8()? != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid statement packet status",
            ));
        }

        let statement_id = payload.read_u32::<LE>()?;
        let num_columns = payload.read_u16::<LE>()?;
        let num_params = payload.read_u16::<LE>()?;
        payload.read_u8()?;
        let warning_count = payload.read_u16::<LE>()?;

        Ok(StmtPacket {
            statement_id,
            num_columns,
            num_params,
            warning_count,
        })
    }

    /// Value of the statement_id field of a statement packet.
    pub fn statement_id(&self) -> u32 {
        self.statement_id
    }

    /// Value of the num_columns field of a statement packet.
    pub fn num_columns(&self) -> u16 {
        self.num_columns
    }

    /// Value of the num_params field of a statement packet.
    pub fn num_params(&self) -> u16 {
        self.num_params
    }

    /// Value of the warning_count field of a statement packet.
    pub fn warning_count(&self) -> u16 {
        self.warning_count
    }
}

/// Null-bitmap.
///
/// http://dev.mysql.com/doc/internals/en/null-bitmap.html
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NullBitmap<T, U: AsRef<[u8]> = Vec<u8>>(U, PhantomData<T>);

impl<T: SerializationSide> NullBitmap<T, Vec<u8>> {
    /// Creates new null-bitmap for a given number of columns.
    pub fn new(num_columns: usize) -> Self {
        Self::from_bytes(vec![0; Self::bitmap_len(num_columns)])
    }

    /// Will read null-bitmap for a given number of columns from `input`.
    pub fn read(input: &mut &[u8], num_columns: usize) -> Self {
        let bitmap_len = Self::bitmap_len(num_columns);
        assert!(input.len() >= bitmap_len);

        let bitmap = Self::from_bytes(input[..bitmap_len].to_vec());
        *input = &input[bitmap_len..];

        bitmap
    }
}

impl<T: SerializationSide, U: AsRef<[u8]>> NullBitmap<T, U> {
    pub fn bitmap_len(num_columns: usize) -> usize {
        (num_columns + 7 + T::BIT_OFFSET) / 8
    }

    fn byte_and_bit(&self, column_index: usize) -> (usize, u8) {
        let offset = column_index + T::BIT_OFFSET;
        let byte = offset / 8;
        let bit = 1 << (offset % 8) as u8;

        assert!(byte < self.0.as_ref().len());

        (byte, bit)
    }

    /// Creates new null-bitmap from given bytes.
    pub fn from_bytes(bytes: U) -> Self {
        Self(bytes, PhantomData)
    }

    /// Returns `true` if given column is `NULL` in this `NullBitmap`.
    pub fn is_null(&self, column_index: usize) -> bool {
        let (byte, bit) = self.byte_and_bit(column_index);
        self.0.as_ref()[byte] & bit > 0
    }
}

impl<T: SerializationSide, U: AsRef<[u8]> + AsMut<[u8]>> NullBitmap<T, U> {
    /// Sets flag value for given column.
    pub fn set(&mut self, column_index: usize, is_null: bool) {
        let (byte, bit) = self.byte_and_bit(column_index);
        if is_null {
            self.0.as_mut()[byte] |= bit
        } else {
            self.0.as_mut()[byte] &= !bit
        }
    }
}

impl<T, U: AsRef<[u8]>> AsRef<[u8]> for NullBitmap<T, U> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ComStmtExecuteRequestBuilder {
    body: Vec<u8>,
    bitmap_len: usize,
    params_added: u16,
}

impl ComStmtExecuteRequestBuilder {
    pub const NULL_BITMAP_OFFSET: usize = 10;

    pub fn new(stmt_id: u32) -> Self {
        let mut body = Vec::with_capacity(1024);
        body.resize(10, 0);
        // command
        body[0] = Command::COM_STMT_EXECUTE as u8;
        // stmt-id
        LE::write_u32(&mut body[1..5], stmt_id);
        // iteration-count
        body[6] = 1;

        Self {
            body,
            bitmap_len: 0,
            params_added: 0,
        }
    }

    pub fn build(mut self, params: &[Value]) -> (Vec<u8>, bool) {
        if params.len() > 0 {
            self.bitmap_len = NullBitmap::<ClientSide>::bitmap_len(params.len());
            let meta_len = params.len() * 2;
            let data_len: usize = params.iter().map(Value::bin_len).sum();

            let total_len = self.body.len() + self.bitmap_len + 1 + meta_len + data_len;
            let as_long_data = total_len > MAX_PAYLOAD_LEN;

            self.body
                .resize(self.body.len() + self.bitmap_len + 1 + meta_len, 0);
            self.body[Self::NULL_BITMAP_OFFSET + self.bitmap_len] = 1;

            for value in params {
                self.add_param(value, as_long_data);
            }

            (self.body, as_long_data)
        } else {
            (self.body, false)
        }
    }

    fn add_param(&mut self, value: &Value, as_long_data: bool) -> u64 {
        let param_index = self.params_added as usize;
        self.params_added += 1;

        let mut write = true;

        match value {
            Value::NULL => {
                self.set_null_flag(param_index);
                self.set_type(param_index, ColumnType::MYSQL_TYPE_NULL);
                write = false;
            }
            Value::Bytes(_) => {
                self.set_type(param_index, ColumnType::MYSQL_TYPE_VAR_STRING);
                write = !as_long_data;
            }
            Value::Int(_) => {
                self.set_type(param_index, ColumnType::MYSQL_TYPE_LONGLONG);
            }
            Value::UInt(_) => {
                self.set_type(param_index, ColumnType::MYSQL_TYPE_LONGLONG);
                self.set_unsigned(param_index);
            }
            Value::Double(_) => {
                self.set_type(param_index, ColumnType::MYSQL_TYPE_DOUBLE);
            }
            Value::Float(_) => {
                self.set_type(param_index, ColumnType::MYSQL_TYPE_FLOAT);
            }
            Value::Date(..) => {
                self.set_type(param_index, ColumnType::MYSQL_TYPE_DATETIME);
            }
            Value::Time(..) => {
                self.set_type(param_index, ColumnType::MYSQL_TYPE_TIME);
            }
        }

        if write {
            self.body.write_bin_value(value).expect("out of memory")
        } else {
            0
        }
    }

    fn set_type(&mut self, param_index: usize, param_type: ColumnType) {
        let param_meta_offset = self.param_meta_index_offset(param_index);
        self.body[param_meta_offset] = param_type as u8;
    }

    fn set_unsigned(&mut self, param_index: usize) {
        let param_meta_offset = self.param_meta_index_offset(param_index);
        self.body[param_meta_offset + 1] = 0x80;
    }

    fn set_null_flag(&mut self, param_index: usize) {
        let end = Self::NULL_BITMAP_OFFSET + self.bitmap_len;
        let bitmap_bytes = &mut self.body[Self::NULL_BITMAP_OFFSET..end];

        NullBitmap::<ClientSide, _>::from_bytes(bitmap_bytes).set(param_index, true);
    }

    fn param_meta_index_offset(&self, param_index: usize) -> usize {
        Self::NULL_BITMAP_OFFSET + self.bitmap_len + 1 + 2 * param_index
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ComStmtSendLongData {
    body: Vec<u8>,
}

impl ComStmtSendLongData {
    pub fn new(stmt_id: u32, param_index: usize, data: &[u8]) -> Self {
        let mut body = Vec::with_capacity(1 + 4 + 2 + data.len());

        body.push(Command::COM_STMT_SEND_LONG_DATA as u8);
        body.write_u32::<LE>(stmt_id).expect("unreachable");
        body.write_u16::<LE>(param_index as u16)
            .expect("unreachable");
        body.extend_from_slice(data);

        Self { body }
    }
}

impl AsRef<[u8]> for ComStmtSendLongData {
    fn as_ref(&self) -> &[u8] {
        &*self.body
    }
}

impl Into<Vec<u8>> for ComStmtSendLongData {
    fn into(self) -> Vec<u8> {
        self.body
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ComStmtClose {
    body: Vec<u8>,
}

impl ComStmtClose {
    pub fn new(stmt_id: u32) -> Self {
        let mut body = Vec::with_capacity(1 + 4);
        body.push(Command::COM_STMT_CLOSE as u8);
        body.write_u32::<LE>(stmt_id).expect("unreachable");
        Self { body }
    }

    pub fn set_id(&mut self, stmt_id: u32) {
        LE::write_u32(&mut self.body[1..], stmt_id);
    }
}

impl AsRef<[u8]> for ComStmtClose {
    fn as_ref(&self) -> &[u8] {
        &*self.body
    }
}

impl Into<Vec<u8>> for ComStmtClose {
    fn into(self) -> Vec<u8> {
        self.body
    }
}

/// Registers a slave at the master. Should be sent before requesting a binlog events
/// with `COM_BINLOG_DUMP`.
///
/// For serialization use `Into<Vec<u8>> for ComRegisterSlave` impl.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ComRegisterSlave {
    /// The slaves server-id.
    pub server_id: u32,
    /// The host name or IP address of the slave to be reported to the master during slave
    /// registration. Usually empty.
    pub hostname: RawText,
    /// The account user name of the slave to be reported to the master during slave registration.
    /// Usually empty.
    ///
    /// # Note
    ///
    /// Serialization will truncate this value if length is greater than 255 bytes.
    pub user: RawText,
    /// The account password of the slave to be reported to the master during slave registration.
    /// Usually empty.
    ///
    /// # Note
    ///
    /// Serialization will truncate this value if length is greater than 255 bytes.
    pub password: RawText,
    /// The TCP/IP port number for connecting to the slave, to be reported to the master during
    /// slave registration. Usually empty.
    ///
    /// # Note
    ///
    /// Serialization will truncate this value if length is greater than 255 bytes.
    pub port: u16,
    /// Ignored.
    pub replication_rank: u32,
    /// Usually 0. Appears as "master id" in `SHOW SLAVE HOSTS` on the master. Unknown what else
    /// it impacts.
    pub master_id: u32,
}

impl ComRegisterSlave {
    /// Creates new `ComRegisterSlave` with the given server identifier. Other fields will be empty.
    pub fn new(server_id: u32) -> Self {
        Self {
            server_id,
            hostname: Default::default(),
            user: Default::default(),
            password: Default::default(),
            port: Default::default(),
            replication_rank: Default::default(),
            master_id: Default::default(),
        }
    }

    /// Returns length of serialized instance (in bytes).
    pub fn len(&self) -> usize {
        let mut len = 0;

        len += 1; // [15] COM_REGISTER_SLAVE
        len += 4; // server-id
        len += 1; // slaves hostname length
        len += min(u8::MAX as usize, self.hostname.0.len()); // slaves hostname
        len += 1; // slaves user len
        len += min(u8::MAX as usize, self.user.0.len()); // slaves user
        len += 1; // slaves password len
        len += min(u8::MAX as usize, self.password.0.len()); // slaves password
        len += 2; // slaves mysql-port
        len += 4; // replication rank
        len += 4; // master id

        len
    }

    /// Writes this instance to the given stream.
    pub fn write<T: Write>(&self, mut output: T) -> io::Result<()> {
        let hostname_len = min(u8::MAX as usize, self.hostname.0.len());
        let user_len = min(u8::MAX as usize, self.user.0.len());
        let password_len = min(u8::MAX as usize, self.password.0.len());

        output.write_u8(Command::COM_REGISTER_SLAVE as u8)?;
        output.write_u32::<LE>(self.server_id)?;
        output.write_u8(hostname_len as u8)?;
        output.limit(S(hostname_len)).write_all(&self.hostname.0)?;
        output.write_u8(user_len as u8)?;
        output.limit(S(user_len)).write_all(&self.user.0)?;
        output.write_u8(password_len as u8)?;
        output.limit(S(password_len)).write_all(&self.password.0)?;
        output.write_u16::<LE>(self.port)?;
        output.write_u32::<LE>(self.replication_rank)?;
        output.write_u32::<LE>(self.master_id)?;

        Ok(())
    }

    /// Reads serialized `Self` from the given stream.
    ///
    /// Returns `(InvalidData, "unexpected")` in case of invalid content.
    pub fn read<T: Read>(mut input: T) -> io::Result<Self> {
        let cmd = input.read_u8()?;

        if cmd != Command::COM_REGISTER_SLAVE as u8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected"));
        }

        let server_id = input.read_u32::<LE>().unwrap();
        let hostname_len = input.read_u8().unwrap() as usize;
        let mut hostname = vec![0_u8; hostname_len];
        input.read_exact(&mut hostname).unwrap();
        let user_len = input.read_u8().unwrap() as usize;
        let mut user = vec![0_u8; user_len];
        input.read_exact(&mut user).unwrap();
        let password_len = input.read_u8().unwrap() as usize;
        let mut password = vec![0_u8; password_len];
        input.read_exact(&mut password).unwrap();
        let port = input.read_u16::<LE>().unwrap();
        let replication_rank = input.read_u32::<LE>().unwrap();
        let master_id = input.read_u32::<LE>().unwrap();

        Ok(Self {
            server_id,
            hostname: RawText(hostname),
            user: RawText(user),
            password: RawText(password),
            port,
            replication_rank,
            master_id,
        })
    }
}

/// Command to dump a table.
///
/// For serialization use `Into<Vec<u8>> for ComTableDump` impl.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ComTableDump {
    /// Database name.
    ///
    /// # Note
    ///
    /// Serialization will truncate this value if length is greater than 255 bytes.
    pub database: Vec<u8>,
    /// Table name.
    ///
    /// # Note
    ///
    /// Serialization will truncate this value if length is greater than 255 bytes.
    pub table: Vec<u8>,
}

impl ComTableDump {
    /// Creates new instance.
    pub fn new(database: Vec<u8>, table: Vec<u8>) -> Self {
        Self { database, table }
    }

    /// Returns `database` as a UTF-8 string (lossy converted).
    pub fn get_database(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.database)
    }

    /// Returns `table` as a UTF-8 string (lossy converted).
    pub fn get_table(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.table)
    }

    /// Returns length of serialized instance (in bytes).
    pub fn len(&self) -> usize {
        let mut len = 0;

        len += 1; // [13] COM_TABLE_DUMP
        len += 1; // database_len
        len += min(u8::MAX as usize, self.database.len()); // database name
        len += 1; // table_len
        len += min(u8::MAX as usize, self.table.len()); // table name

        len
    }

    /// Writes this instance to the given stream.
    pub fn write<T: Write>(&self, mut output: T) -> io::Result<()> {
        let database_len = min(u8::MAX as usize, self.database.len());
        let table_len = min(u8::MAX as usize, self.table.len());

        output.write_u8(Command::COM_TABLE_DUMP as u8)?;
        output.write_u8(database_len as u8)?;
        output.limit(S(database_len)).write_all(&self.database)?;
        output.write_u8(table_len as u8)?;
        output.limit(S(table_len)).write_all(&self.table)?;

        Ok(())
    }

    /// Reads serialized `Self` from the given stream.
    ///
    /// Returns `(InvalidData, "unexpected")` in case of invalid content.
    pub fn read<T: Read>(mut input: T) -> io::Result<Self> {
        let cmd = input.read_u8()?;

        if cmd != Command::COM_TABLE_DUMP as u8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected"));
        }

        let database_len = input.read_u8()? as usize;
        let mut database = vec![0_u8; database_len];
        input.read_exact(&mut database)?;
        let table_len = input.read_u8()? as usize;
        let mut table = vec![0_u8; table_len];
        input.read_exact(&mut table)?;

        Ok(Self { database, table })
    }
}

impl fmt::Debug for ComTableDump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComTableDump")
            .field("database", &self.get_database())
            .field("table", &self.get_table())
            .finish()
    }
}

my_bitflags! {
    BinlogDumpFlags, u16,

    /// Empty flags of a `LoadEvent`.
    pub struct BinlogDumpFlags: u16 {
        /// If there is no more event to send a EOF_Packet instead of blocking the connection
        const BINLOG_DUMP_NON_BLOCK = 0x01;
        const BINLOG_THROUGH_POSITION = 0x02;
        const BINLOG_THROUGH_GTID = 0x04;
    }
}

/// Command to request a binlog-stream from the master starting a given position.
///
/// For serialization use `Into<Vec<u8>> for ComBinlogDump` impl.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ComBinlogDump {
    /// Position in the binlog-file to start the stream with (`0` by default).
    pub pos: u32,
    /// Command flags (empty by default).
    ///
    /// Only `BINLOG_DUMP_NON_BLOCK` is supported for this command.
    pub flags: BinlogDumpFlags,
    /// Server id of this slave.
    pub server_id: u32,
    /// Filename of the binlog on the master.
    ///
    /// If the binlog-filename is empty, the server will send the binlog-stream of the first known
    /// binlog.
    pub filename: Vec<u8>,
}

impl ComBinlogDump {
    /// Creates new instance with default values for `pos` and `flags`.
    pub fn new(server_id: u32) -> Self {
        Self {
            pos: 0,
            flags: BinlogDumpFlags::empty(),
            server_id,
            filename: vec![],
        }
    }

    /// Returns `filename` as a UTF-8 string (lossy converted).
    pub fn get_filename(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.filename)
    }

    /// Returns parsed `flags` field with unknown bits truncated.
    pub fn get_flags(&self) -> BinlogDumpFlags {
        self.flags
    }

    /// Defines filename for this instance.
    pub fn with_filename(mut self, filename: Vec<u8>) -> Self {
        self.filename = filename;
        self
    }

    /// Defines flags for this instance.
    pub fn with_flags(mut self, flags: BinlogDumpFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Defines position for this instance.
    pub fn with_pos(mut self, pos: u32) -> Self {
        self.pos = pos;
        self
    }

    /// Returns length of serialized instance (in bytes).
    pub fn len(&self) -> usize {
        let mut len = S(0);

        len += S(1); // [12] COM_BINLOG_DUMP
        len += S(4); // binlog-pos
        len += S(2); // flags
        len += S(4); // server-id
        len += S(self.filename.len()); // binlog-filename

        len.0
    }

    /// Writes this instance to the given stream.
    pub fn write<T: Write>(&self, mut output: T) -> io::Result<()> {
        output.write_u8(Command::COM_BINLOG_DUMP as u8)?;
        output.write_u32::<LE>(self.pos)?;
        output.write_u16::<LE>(self.flags.bits())?;
        output.write_u32::<LE>(self.server_id)?;
        output.write_all(&self.filename)?;

        Ok(())
    }

    /// Reads serialized `Self` from the given stream.
    ///
    /// Returns `(InvalidData, "unexpected")` in case of invalid content.
    ///
    /// # Warning
    ///
    /// It'll read entire stream as a `filename` because `filename` is EOF-terminated by definition.
    pub fn read<T: Read>(mut input: T) -> io::Result<Self> {
        let cmd = input.read_u8()?;

        if cmd != Command::COM_BINLOG_DUMP as u8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected"));
        }

        let pos = input.read_u32::<LE>()?;
        let flags = input.read_u16::<LE>()?;
        let server_id = input.read_u32::<LE>()?;
        let mut filename = Vec::new();
        input.read_to_end(&mut filename)?;

        Ok(Self {
            pos,
            flags: BinlogDumpFlags::from_bits_truncate(flags),
            server_id,
            filename,
        })
    }
}

/// SID block is a part of the `COM_BINLOG_DUMP_GTID` command.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SidBlock {
    /// SID value.
    pub sid: [u8; Self::SID_LEN],
    /// Pairs of `(<start>, <end>)` (empty by default).
    pub intervals: Vec<(u64, u64)>,
}

impl SidBlock {
    pub const SID_LEN: usize = 16;

    /// Creates new instance.
    pub fn new(sid: [u8; Self::SID_LEN]) -> Self {
        Self {
            sid,
            intervals: Default::default(),
        }
    }

    /// Adds an interval to this instance.
    pub fn with_interval(mut self, interval: (u64, u64)) -> Self {
        self.intervals.push(interval);
        self
    }

    /// Returns length of serialized instance (in bytes).
    pub fn len(&self) -> usize {
        let mut len = S(0);

        len += S(Self::SID_LEN); // SID
        len += S(8); // n_intervals
        len += S(16 * self.intervals.len()); // intervals

        len.0
    }

    /// Writes this instance to the given stream.
    pub fn write<T: Write>(&self, mut output: T) -> io::Result<()> {
        output.write_all(&self.sid[..])?;
        output.write_u64::<LE>(self.intervals.len() as u64)?;
        for (start, end) in &self.intervals {
            output.write_u64::<LE>(*start)?;
            output.write_u64::<LE>(*end)?;
        }
        Ok(())
    }

    /// Reads serialized `Self` from the given stream.
    ///
    /// Returns `(InvalidData, "unexpected")` in case of invalid content.
    pub fn read<T: Read>(mut input: T) -> io::Result<Self> {
        let mut sid = [0_u8; 16];
        input.read_exact(&mut sid[..])?;

        let n_intervals = input.read_u64::<LE>()?;

        let mut intervals = Vec::new();
        for _ in 0..n_intervals {
            let start = input.read_u64::<LE>()?;
            let end = input.read_u64::<LE>()?;
            intervals.push((start, end));
        }

        Ok(Self { sid, intervals })
    }
}

/// Command to request a binlog-stream from the master starting a given position.
///
/// For serialization use `Into<Vec<u8>> for ComBinlogDumpGtid` impl.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ComBinlogDumpGtid {
    /// Command flags (empty by default).
    pub flags: BinlogDumpFlags,
    /// Server id of this slave.
    pub server_id: u32,
    /// Filename of the binlog on the master.
    ///
    /// If the binlog-filename is empty, the server will send the binlog-stream of the first known
    /// binlog.
    ///
    /// # Note
    ///
    /// Serialization will truncate this value if length is greater than 2^32 - 1 bytes.
    pub filename: Vec<u8>,
    /// Position in the binlog-file to start the stream with (`0` by default).
    pub pos: u64,
    /// SID blocks (empty by default).
    ///
    /// # Note
    ///
    /// Serialization will return an error if lenght of a serialized value
    /// is greater than 2^32 - 1 bytes.
    pub sid_blocks: Vec<SidBlock>,
}

impl ComBinlogDumpGtid {
    /// Creates new instance with default values for `pos`, `data` and `flags` fields.
    pub fn new(server_id: u32) -> Self {
        Self {
            pos: 0,
            flags: BinlogDumpFlags::empty(),
            server_id,
            filename: vec![],
            sid_blocks: Default::default(),
        }
    }

    /// Returns `filename` as a UTF-8 string (lossy converted).
    pub fn get_filename(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.filename)
    }

    /// Returns parsed `flags` field with unknown bits truncated.
    pub fn get_flags(&self) -> BinlogDumpFlags {
        self.flags
    }

    /// Defines filename for this instance.
    pub fn with_filename(mut self, filename: Vec<u8>) -> Self {
        self.filename = filename;
        self
    }

    /// Defines flags for this instance.
    pub fn with_flags(mut self, flags: BinlogDumpFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Defines position for this instance.
    pub fn with_pos(mut self, pos: u64) -> Self {
        self.pos = pos;
        self
    }

    /// Adds SID block to this instance.
    pub fn with_sid_blocks<T>(mut self, sid_blocks: T) -> Self
    where
        T: IntoIterator<Item = SidBlock>,
    {
        self.sid_blocks = sid_blocks.into_iter().collect();
        self
    }

    /// Returns length of serialized instance (in bytes).
    pub fn len(&self) -> usize {
        let mut len = S(0);

        len += S(1); // [1e] COM_BINLOG_DUMP_GTID
        len += S(2); // flags
        len += S(4); // server-id
        len += S(4); // binlog-filename-len
        len += S(min(u32::MAX as usize, self.filename.len())); // binlog-filename
        len += S(8); // binlog-pos
        len += S(4); // data-size
        len += S(8); // n_sids
        len += S(min(
            u32::MAX as usize - 8,
            self.sid_blocks.iter().map(SidBlock::len).sum(),
        )); // data

        len.0
    }

    /// Writes this instance to the given stream.
    pub fn write<T: Write>(&self, mut output: T) -> io::Result<()> {
        let filename_len = min(u32::MAX as usize, self.filename.len());

        output.write_u8(Command::COM_BINLOG_DUMP_GTID as u8)?;
        output.write_u16::<LE>(self.flags.bits())?;
        output.write_u32::<LE>(self.server_id)?;
        output.write_u32::<LE>(filename_len as u32)?;
        output.write_all(&self.filename[..filename_len])?;
        output.write_u64::<LE>(self.pos)?;

        let n_sids = min(u64::MAX as usize, self.sid_blocks.len());

        let mut data_len = S(8);
        for block in &self.sid_blocks {
            data_len += S(block.len());
        }

        output.write_u32::<LE>(data_len.0 as u32)?;
        output.write_u64::<LE>(n_sids as u64)?;

        let mut output = output.limit(S(data_len.0));

        for sid_block in &self.sid_blocks {
            sid_block.write(&mut output)?;
        }

        Ok(())
    }

    /// Reads serialized `Self` from the given stream.
    ///
    /// Returns `(InvalidData, "unexpected")` in case of invalid content.
    ///
    /// # Warning
    ///
    /// It'll read entire stream as a `filename` because `filename` is EOF-terminated by definition.
    pub fn read<T: Read>(mut input: T) -> io::Result<Self> {
        let cmd = input.read_u8()?;

        if cmd != Command::COM_BINLOG_DUMP_GTID as u8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected"));
        }

        let flags = input.read_u16::<LE>()?;
        let server_id = input.read_u32::<LE>()?;
        let filename_len = input.read_u32::<LE>()? as usize;
        let mut filename = vec![0_u8; filename_len];
        input.read_exact(&mut filename)?;
        let pos = input.read_u64::<LE>()?;
        let mut sid_blocks = Vec::new();
        let data_len = input.read_u32::<LE>()? as usize;
        if data_len > 0 {
            let mut input = input.limit(S(data_len));
            let n_sids = input.read_u64::<LE>()?;
            for _ in 0..n_sids {
                input.get_limit();
                let block = SidBlock::read(&mut input)?;
                sid_blocks.push(block);
            }
        }

        Ok(Self {
            flags: BinlogDumpFlags::from_bits_truncate(flags),
            server_id,
            filename,
            pos,
            sid_blocks,
        })
    }
}

/// Each Semi Sync Binlog Event with the `SEMI_SYNC_ACK_REQ` flag set the slave has to acknowledge
/// with Semi-Sync ACK packet.
pub struct SemiSyncAckPacket {
    pub position: u64,
    pub filename: Vec<u8>,
}

impl SemiSyncAckPacket {
    /// Returns length of serialized instance (in bytes).
    pub fn len(&self) -> usize {
        let mut len = S(0);

        len += S(1); // [ef]
        len += S(8); // log position
        len += S(self.filename.len()); // log filename

        len.0
    }

    /// Writes this instance to the given stream.
    pub fn write<T: Write>(&self, mut output: T) -> io::Result<()> {
        output.write_u8(0xef)?;
        output.write_u64::<LE>(self.position)?;
        output.write_all(&self.filename)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::{
        CapabilityFlags, ColumnFlags, ColumnType, StatusFlags, UTF8_GENERAL_CI,
    };

    proptest::proptest! {
        #[test]
        fn com_table_dump_roundtrip(database: Vec<u8>, table: Vec<u8>) {
            let cmd = ComTableDump { database, table };

            let mut output = Vec::new();
            cmd.write(&mut output)?;

            assert_eq!(cmd, ComTableDump::read(&output[..])?);
        }

        #[test]
        fn com_binlog_dump_roundtrip(
            server_id: u32,
            filename: Vec<u8>,
            pos: u32,
            flags: u16,
        ) {
            let mut cmd = ComBinlogDump::new(server_id).with_filename(filename).with_pos(pos);
            cmd.flags = crate::packets::BinlogDumpFlags::from_bits_truncate(flags);

            let mut output = Vec::new();
            cmd.write(&mut output)?;

            assert_eq!(cmd, ComBinlogDump::read(&output[..])?);
        }

        #[test]
        fn com_register_slave_roundtrip(
            server_id: u32,
            hostname in r"\w{0,256}",
            user in r"\w{0,256}",
            password in r"\w{0,256}",
            port: u16,
            replication_rank: u32,
            master_id: u32,
        ) {
            use crate::misc::RawText;

            let cmd = ComRegisterSlave {
                server_id,
                hostname: RawText(hostname.as_bytes().to_vec()),
                user: RawText(user.as_bytes().to_vec()),
                password: RawText(password.as_bytes().to_vec()),
                port,
                replication_rank,
                master_id,
            };

            let mut output = Vec::new();
            let write_result = cmd.write(&mut output);

            if hostname.len() > 255 || user.len() > 255 || password.len() > 255 {
                assert_eq!(write_result.unwrap_err().kind(), std::io::ErrorKind::WriteZero);
                return Ok(());
            } else {
                write_result?;
            }

            assert_eq!(cmd, ComRegisterSlave::read(&output[..])?);
        }

        #[test]
        fn com_binlog_dump_gtid_roundtrip(
            flags: u16,
            server_id: u32,
            filename: Vec<u8>,
            pos: u64,
            n_sid_blocks in 0_u64..1024,
        ) {
            let mut cmd = ComBinlogDumpGtid::new(server_id).with_filename(filename).with_pos(pos);
            cmd.flags = crate::packets::BinlogDumpFlags::from_bits_truncate(flags);

            let mut sid_blocks = Vec::new();
            for i in 0..n_sid_blocks {
                let mut block = SidBlock::new([i as u8; 16]);
                for j in 0..i {
                    block = block.with_interval((i, j));
                }
                sid_blocks.push(block);
            }

            cmd = cmd.with_sid_blocks(sid_blocks);

            let mut output = Vec::new();
            cmd.write(&mut output)?;

            assert_eq!(cmd, ComBinlogDumpGtid::read(&output[..])?);
        }
    }

    #[test]
    fn should_parse_local_infile_packet() {
        const LIP: &[u8] = b"\xfbfile_name";

        let lip = parse_local_infile_packet(LIP).unwrap();
        assert_eq!(lip.file_name_str(), "file_name");
    }

    #[test]
    fn should_parse_stmt_packet() {
        const SP: &[u8] = b"\x00\x01\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00";
        const SP_2: &[u8] = b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let sp = parse_stmt_packet(SP).unwrap();
        assert_eq!(sp.statement_id(), 0x01);
        assert_eq!(sp.num_columns(), 0x01);
        assert_eq!(sp.num_params(), 0x02);
        assert_eq!(sp.warning_count(), 0x00);

        let sp = parse_stmt_packet(SP_2).unwrap();
        assert_eq!(sp.statement_id(), 0x01);
        assert_eq!(sp.num_columns(), 0x00);
        assert_eq!(sp.num_params(), 0x00);
        assert_eq!(sp.warning_count(), 0x00);
    }

    #[test]
    fn should_parse_handshake_packet() {
        const HSP: &[u8] = b"\x0a5.5.5-10.0.17-MariaDB-log\x00\x0b\x00\
                             \x00\x00\x64\x76\x48\x40\x49\x2d\x43\x4a\x00\xff\xf7\x08\x02\x00\
                             \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2a\x34\x64\
                             \x7c\x63\x5a\x77\x6b\x34\x5e\x5d\x3a\x00";

        const HSP_2: &[u8] = b"\x0a\x35\x2e\x36\x2e\x34\x2d\x6d\x37\x2d\x6c\x6f\
                               \x67\x00\x56\x0a\x00\x00\x52\x42\x33\x76\x7a\x26\x47\x72\x00\xff\
                               \xff\x08\x02\x00\x0f\xc0\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                               \x00\x2b\x79\x44\x26\x2f\x5a\x5a\x33\x30\x35\x5a\x47\x00\x6d\x79\
                               \x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\
                               \x6f\x72\x64\x00\x00";

        let hsp = parse_handshake_packet(HSP).unwrap();
        assert_eq!(hsp.protocol_version, 0x0a);
        assert_eq!(hsp.server_version_str(), "5.5.5-10.0.17-MariaDB-log");
        assert_eq!(hsp.server_version_parsed(), Some((5, 5, 5)));
        assert_eq!(hsp.maria_db_server_version_parsed(), Some((10, 0, 17)));
        assert_eq!(hsp.connection_id(), 0x0b);
        assert_eq!(hsp.scramble_1_ref(), b"dvH@I-CJ");
        assert_eq!(
            hsp.capabilities(),
            CapabilityFlags::from_bits_truncate(0xf7ff)
        );
        assert_eq!(hsp.default_collation(), 0x08);
        assert_eq!(hsp.status_flags(), StatusFlags::from_bits_truncate(0x0002));
        assert_eq!(hsp.scramble_2_ref(), Some(&b"*4d|cZwk4^]:"[..]));
        assert_eq!(hsp.auth_plugin_name_ref(), None);

        let hsp = parse_handshake_packet(HSP_2).unwrap();
        assert_eq!(hsp.protocol_version, 0x0a);
        assert_eq!(hsp.server_version_str(), "5.6.4-m7-log");
        assert_eq!(hsp.server_version_parsed(), Some((5, 6, 4)));
        assert_eq!(hsp.maria_db_server_version_parsed(), None);
        assert_eq!(hsp.connection_id(), 0x0a56);
        assert_eq!(hsp.scramble_1_ref(), b"RB3vz&Gr");
        assert_eq!(
            hsp.capabilities(),
            CapabilityFlags::from_bits_truncate(0xc00fffff)
        );
        assert_eq!(hsp.default_collation(), 0x08);
        assert_eq!(hsp.status_flags(), StatusFlags::from_bits_truncate(0x0002));
        assert_eq!(hsp.scramble_2_ref(), Some(&b"+yD&/ZZ305ZG"[..]));
        assert_eq!(
            hsp.auth_plugin_name_ref(),
            Some(&b"mysql_native_password"[..])
        );
    }

    #[test]
    fn should_parse_err_packet() {
        const ERR_PACKET: &[u8] = b"\xff\x48\x04\x23\x48\x59\x30\x30\x30\x4e\x6f\x20\x74\x61\x62\
        \x6c\x65\x73\x20\x75\x73\x65\x64";
        const ERR_PACKET_NO_STATE: &[u8] = b"\xff\x10\x04\x54\x6f\x6f\x20\x6d\x61\x6e\x79\x20\x63\
        \x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x73";
        const PROGRESS_PACKET: &[u8] = b"\xff\xff\xff\x01\x01\x0a\xcc\x5b\x00\x0astage name";

        let err_packet = parse_err_packet(ERR_PACKET, CapabilityFlags::empty()).unwrap();
        assert!(err_packet.is_error());
        assert_eq!(err_packet.error_code(), 1096);
        assert_eq!(err_packet.sql_state_str(), "HY000");
        assert_eq!(err_packet.message_str(), "No tables used");

        let err_packet =
            parse_err_packet(ERR_PACKET_NO_STATE, CapabilityFlags::CLIENT_PROTOCOL_41).unwrap();
        assert!(err_packet.is_error());
        assert_eq!(err_packet.error_code(), 1040);
        assert_eq!(err_packet.sql_state_str(), "HY000");
        assert_eq!(err_packet.message_str(), "Too many connections");

        let err_packet =
            parse_err_packet(PROGRESS_PACKET, CapabilityFlags::CLIENT_PROGRESS_OBSOLETE).unwrap();
        assert!(err_packet.is_progress_report());
        let progress_report = err_packet.progress_report();
        assert_eq!(progress_report.stage(), 1);
        assert_eq!(progress_report.max_stage(), 10);
        assert_eq!(progress_report.progress(), 23500);
        assert_eq!(progress_report.stage_info_str(), "stage name");
    }

    #[test]
    fn should_parse_column_packet() {
        const COLUMN_PACKET: &[u8] = b"\x03def\x06schema\x05table\x09org_table\x04name\
              \x08org_name\x0c\x21\x00\x0F\x00\x00\x00\x00\x01\x00\x08\x00\x00";
        let column = Column::read(COLUMN_PACKET).unwrap();
        assert_eq!(column.schema_str(), "schema");
        assert_eq!(column.table_str(), "table");
        assert_eq!(column.org_table_str(), "org_table");
        assert_eq!(column.name_str(), "name");
        assert_eq!(column.org_name_str(), "org_name");
        assert_eq!(column.character_set(), UTF8_GENERAL_CI);
        assert_eq!(column.column_length(), 15);
        assert_eq!(column.column_type(), ColumnType::MYSQL_TYPE_DECIMAL);
        assert_eq!(column.flags(), ColumnFlags::NOT_NULL_FLAG);
        assert_eq!(column.decimals(), 8);
    }

    #[test]
    fn should_parse_auth_switch_request() {
        const PAYLOAD: &[u8] = b"\xfe\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\
                                 \x73\x73\x77\x6f\x72\x64\x00\x7a\x51\x67\x34\x69\x36\x6f\x4e\x79\
                                 \x36\x3d\x72\x48\x4e\x2f\x3e\x2d\x62\x29\x41\x00";
        let packet = parse_auth_switch_request(PAYLOAD).unwrap();
        assert_eq!(packet.auth_plugin().as_bytes(), b"mysql_native_password",);
        assert_eq!(packet.plugin_data(), b"zQg4i6oNy6=rHN/>-b)A",)
    }

    #[test]
    fn should_parse_auth_more_data() {
        const PAYLOAD: &[u8] = b"\x01\x04";
        let packet = parse_auth_more_data(PAYLOAD).unwrap();
        assert_eq!(packet.data(), b"\x04",);
    }

    #[test]
    fn should_parse_ok_packet() {
        const PLAIN_OK: &[u8] = b"\x00\x00\x00\x02\x00\x00\x00";
        const SESS_STATE_SYS_VAR_OK: &[u8] =
            b"\x00\x00\x00\x02\x40\x00\x00\x00\x11\x00\x0f\x0a\x61\
              \x75\x74\x6f\x63\x6f\x6d\x6d\x69\x74\x03\x4f\x46\x46";
        const SESS_STATE_SCHEMA_OK: &[u8] =
            b"\x00\x00\x00\x02\x40\x00\x00\x00\x07\x01\x05\x04\x74\x65\x73\x74";
        const SESS_STATE_TRACK_OK: &[u8] = b"\x00\x00\x00\x02\x40\x00\x00\x00\x04\x02\x02\x01\x31";
        const EOF: &[u8] = b"\xfe\x00\x00\x02\x00";

        // packet starting with 0x00 is not an ok packet if it terminates a result set
        parse_ok_packet(
            PLAIN_OK,
            CapabilityFlags::empty(),
            OkPacketKind::ResultSetTerminator,
        )
        .unwrap_err();

        let ok_packet =
            parse_ok_packet(PLAIN_OK, CapabilityFlags::empty(), OkPacketKind::Other).unwrap();
        assert_eq!(ok_packet.affected_rows(), 0);
        assert_eq!(ok_packet.last_insert_id(), None);
        assert_eq!(
            ok_packet.status_flags(),
            StatusFlags::SERVER_STATUS_AUTOCOMMIT
        );
        assert_eq!(ok_packet.warnings(), 0);
        assert_eq!(ok_packet.info_ref(), None);
        assert_eq!(ok_packet.session_state_info(), None);

        let ok_packet = parse_ok_packet(
            SESS_STATE_SYS_VAR_OK,
            CapabilityFlags::CLIENT_SESSION_TRACK,
            OkPacketKind::Other,
        )
        .unwrap();
        assert_eq!(ok_packet.affected_rows(), 0);
        assert_eq!(ok_packet.last_insert_id(), None);
        assert_eq!(
            ok_packet.status_flags(),
            StatusFlags::SERVER_STATUS_AUTOCOMMIT | StatusFlags::SERVER_SESSION_STATE_CHANGED
        );
        assert_eq!(ok_packet.warnings(), 0);
        assert_eq!(ok_packet.info_ref(), None);
        let sess_state_info = ok_packet.session_state_info().unwrap();
        assert_eq!(
            sess_state_info.decode().unwrap(),
            SessionStateChange::SystemVariable((&b"autocommit"[..]).into(), (&b"OFF"[..]).into())
        );

        let ok_packet = parse_ok_packet(
            SESS_STATE_SCHEMA_OK,
            CapabilityFlags::CLIENT_SESSION_TRACK,
            OkPacketKind::Other,
        )
        .unwrap();
        assert_eq!(ok_packet.affected_rows(), 0);
        assert_eq!(ok_packet.last_insert_id(), None);
        assert_eq!(
            ok_packet.status_flags(),
            StatusFlags::SERVER_STATUS_AUTOCOMMIT | StatusFlags::SERVER_SESSION_STATE_CHANGED
        );
        assert_eq!(ok_packet.warnings(), 0);
        assert_eq!(ok_packet.info_ref(), None);
        let sess_state_info = ok_packet.session_state_info().unwrap();
        assert_eq!(
            sess_state_info.decode().unwrap(),
            SessionStateChange::Schema((&b"test"[..]).into())
        );

        let ok_packet = parse_ok_packet(
            SESS_STATE_TRACK_OK,
            CapabilityFlags::CLIENT_SESSION_TRACK,
            OkPacketKind::Other,
        )
        .unwrap();
        assert_eq!(ok_packet.affected_rows(), 0);
        assert_eq!(ok_packet.last_insert_id(), None);
        assert_eq!(
            ok_packet.status_flags(),
            StatusFlags::SERVER_STATUS_AUTOCOMMIT | StatusFlags::SERVER_SESSION_STATE_CHANGED
        );
        assert_eq!(ok_packet.warnings(), 0);
        assert_eq!(ok_packet.info_ref(), None);
        let sess_state_info = ok_packet.session_state_info().unwrap();
        assert_eq!(
            sess_state_info.decode().unwrap(),
            SessionStateChange::IsTracked(true)
        );

        let ok_packet = parse_ok_packet(
            EOF,
            CapabilityFlags::CLIENT_SESSION_TRACK,
            OkPacketKind::ResultSetTerminator,
        )
        .unwrap();
        assert_eq!(ok_packet.affected_rows(), 0);
        assert_eq!(ok_packet.last_insert_id(), None);
        assert_eq!(
            ok_packet.status_flags(),
            StatusFlags::SERVER_STATUS_AUTOCOMMIT
        );
        assert_eq!(ok_packet.warnings(), 0);
        assert_eq!(ok_packet.info_ref(), None);
        assert_eq!(ok_packet.session_state_info(), None);
    }
}
