//! Matter TLV — the encoding every Interaction Model message is written in.
//!
//! One control byte opens each element: the element type in its low five bits,
//! the tag control in its high three. The tag follows, then the value; a
//! container holds elements until an end-of-container byte. Every number is
//! little-endian. An [`Element`] here is a tag and a [`Value`]; [`encode`]
//! writes one and [`decode`] reads one back, refusing anything malformed with
//! the byte offset where it stopped. Bytes are read over codec's cursor and
//! written with its writer; what a control byte, a tag and a length mean is
//! Matter's, here.

use codec::CodecError;
use codec::cursor::Cursor;
use codec::writer::ByteWriter;

/// Where an element's tag comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    /// No tag: an array element, or a message's top-level structure.
    Anonymous,
    /// A tag whose meaning is given by the enclosing structure.
    Context(u8),
    /// A tag from the Matter common profile.
    Common(u32),
    /// A tag from the profile the message implies.
    Implicit(u32),
    /// A tag with its vendor and profile spelled out.
    FullyQualified {
        vendor: u16,
        profile: u16,
        number: u32,
    },
}

/// What an element holds.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Signed(i64),
    Unsigned(u64),
    Bool(bool),
    Float(f32),
    Double(f64),
    Utf8(String),
    Octets(Vec<u8>),
    Null,
    Structure(Vec<Element>),
    Array(Vec<Element>),
    List(Vec<Element>),
}

/// A tag and its value.
#[derive(Clone, Debug, PartialEq)]
pub struct Element {
    pub tag: Tag,
    pub value: Value,
}

impl Element {
    #[must_use]
    pub const fn new(tag: Tag, value: Value) -> Self {
        Self { tag, value }
    }

    /// A member of a context-tagged structure.
    #[must_use]
    pub const fn context(number: u8, value: Value) -> Self {
        Self::new(Tag::Context(number), value)
    }

    /// The member of a container carrying context tag `number`, if any.
    #[must_use]
    pub fn member(&self, number: u8) -> Option<&Element> {
        self.members()?
            .iter()
            .find(|element| element.tag == Tag::Context(number))
    }

    /// The elements of a structure, array or list.
    #[must_use]
    pub fn members(&self) -> Option<&[Element]> {
        match &self.value {
            Value::Structure(members) | Value::Array(members) | Value::List(members) => {
                Some(members)
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn as_unsigned(&self) -> Option<u64> {
        match self.value {
            Value::Unsigned(n) => Some(n),
            Value::Signed(n) => u64::try_from(n).ok(),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self.value {
            Value::Bool(b) => Some(b),
            _ => None,
        }
    }
}

/// Why bytes are not TLV, and at which offset that became clear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlvError {
    pub offset: usize,
    pub reason: String,
}

impl TlvError {
    fn new(offset: usize, reason: impl Into<String>) -> Self {
        Self {
            offset,
            reason: reason.into(),
        }
    }
}

impl core::fmt::Display for TlvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at offset {}", self.reason, self.offset)
    }
}

impl std::error::Error for TlvError {}

const END_OF_CONTAINER: u8 = 0x18;

/// An element as bytes.
#[must_use]
pub fn encode(element: &Element) -> Vec<u8> {
    let mut out = Vec::new();
    write(element, &mut out);
    out
}

/// One element, and nothing after it.
///
/// # Errors
/// The bytes end inside an element, open a container they never close, use an
/// element type the specification does not define, or go on past the element.
pub fn decode(bytes: &[u8]) -> Result<Element, TlvError> {
    let mut cursor = Cursor::new(bytes);
    let element = element(&mut cursor)?
        .ok_or_else(|| TlvError::new(0, "an end-of-container opens the bytes"))?;
    if !cursor.is_empty() {
        return Err(TlvError::new(
            cursor.position(),
            "bytes continue past the element",
        ));
    }
    Ok(element)
}

fn write(element: &Element, out: &mut Vec<u8>) {
    let (control, tag_bytes) = tag_bytes(element.tag);
    let control_at = out.len();
    out.push(control);
    out.extend_from_slice(&tag_bytes);
    let element_type = match &element.value {
        Value::Signed(n) => write_signed(*n, out),
        Value::Unsigned(n) => write_unsigned(*n, out),
        Value::Bool(false) => 0x08,
        Value::Bool(true) => 0x09,
        Value::Float(f) => {
            out.f32_le(*f);
            0x0A
        }
        Value::Double(f) => {
            out.f64_le(*f);
            0x0B
        }
        Value::Utf8(text) => 0x0C + write_length(text.as_bytes(), out),
        Value::Octets(bytes) => 0x10 + write_length(bytes, out),
        Value::Null => 0x14,
        Value::Structure(members) => write_container(members, out, 0x15),
        Value::Array(members) => write_container(members, out, 0x16),
        Value::List(members) => write_container(members, out, 0x17),
    };
    out[control_at] |= element_type;
}

fn tag_bytes(tag: Tag) -> (u8, Vec<u8>) {
    match tag {
        Tag::Anonymous => (0x00, Vec::new()),
        Tag::Context(n) => (0x20, vec![n]),
        Tag::Common(n) => profile_tag(0x40, n),
        Tag::Implicit(n) => profile_tag(0x80, n),
        Tag::FullyQualified {
            vendor,
            profile,
            number,
        } => {
            let (control, number_bytes) = profile_tag(0xC0, number);
            let mut bytes = vendor.to_le_bytes().to_vec();
            bytes.extend_from_slice(&profile.to_le_bytes());
            bytes.extend_from_slice(&number_bytes);
            (control, bytes)
        }
    }
}

fn profile_tag(short_control: u8, number: u32) -> (u8, Vec<u8>) {
    match u16::try_from(number) {
        Ok(short) => (short_control, short.to_le_bytes().to_vec()),
        Err(_) => (short_control + 0x20, number.to_le_bytes().to_vec()),
    }
}

/// The narrowest of one, two, four or eight little-endian bytes that holds
/// `n`; returns the element type.
fn write_signed(n: i64, out: &mut Vec<u8>) -> u8 {
    let width = match n {
        n if i8::try_from(n).is_ok() => 0,
        n if i16::try_from(n).is_ok() => 1,
        n if i32::try_from(n).is_ok() => 2,
        _ => 3,
    };
    out.extend_from_slice(&n.to_le_bytes()[..1 << width]);
    width
}

fn write_unsigned(n: u64, out: &mut Vec<u8>) -> u8 {
    let width = match n {
        n if u8::try_from(n).is_ok() => 0,
        n if u16::try_from(n).is_ok() => 1,
        n if u32::try_from(n).is_ok() => 2,
        _ => 3,
    };
    out.extend_from_slice(&n.to_le_bytes()[..1 << width]);
    0x04 + width
}

/// The length prefix and the bytes; returns the width's offset into the
/// element type, 0 to 3.
fn write_length(bytes: &[u8], out: &mut Vec<u8>) -> u8 {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let width = if let Ok(v) = u8::try_from(length) {
        out.push(v);
        0
    } else if let Ok(v) = u16::try_from(length) {
        out.u16_le(v);
        1
    } else if let Ok(v) = u32::try_from(length) {
        out.u32_le(v);
        2
    } else {
        out.u64_le(length);
        3
    };
    out.extend_from_slice(bytes);
    width
}

fn write_container(members: &[Element], out: &mut Vec<u8>, element_type: u8) -> u8 {
    for member in members {
        write(member, out);
    }
    out.push(END_OF_CONTAINER);
    element_type
}

/// Where a refused read stopped: codec's cursor does not move on a refusal,
/// so its position is the offset the bytes ran out at.
fn refused(at: usize) -> impl FnOnce(CodecError) -> TlvError {
    move |error| TlvError::new(at, error.message)
}

/// `width` little-endian bytes, zero-extended.
fn unsigned(cursor: &mut Cursor<'_>, width: usize) -> Result<u64, TlvError> {
    let mut buffer = [0u8; 8];
    buffer[..width].copy_from_slice(cursor.take(width).map_err(refused(cursor.position()))?);
    Ok(u64::from_le_bytes(buffer))
}

/// `width` little-endian bytes, sign-extended.
fn signed(cursor: &mut Cursor<'_>, width: usize) -> Result<i64, TlvError> {
    let bytes = cursor.take(width).map_err(refused(cursor.position()))?;
    let fill = if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        0xFF
    } else {
        0x00
    };
    let mut buffer = [fill; 8];
    buffer[..width].copy_from_slice(bytes);
    Ok(i64::from_le_bytes(buffer))
}

/// The element at the cursor; `None` is an end-of-container.
fn element(cursor: &mut Cursor<'_>) -> Result<Option<Element>, TlvError> {
    let start = cursor.position();
    let control = cursor.byte().map_err(refused(start))?;
    if control == END_OF_CONTAINER {
        return Ok(None);
    }
    let tag = tag(cursor, control >> 5)?;
    let element_type = control & 0x1F;
    let value = match element_type {
        0x00..=0x03 => Value::Signed(signed(cursor, 1 << element_type)?),
        0x04..=0x07 => Value::Unsigned(unsigned(cursor, 1 << (element_type - 4))?),
        0x08 => Value::Bool(false),
        0x09 => Value::Bool(true),
        0x0A => Value::Float(cursor.f32_le().map_err(refused(cursor.position()))?),
        0x0B => Value::Double(cursor.f64_le().map_err(refused(cursor.position()))?),
        0x0C..=0x0F => {
            let at = cursor.position();
            let bytes = string(cursor, 1 << (element_type - 0x0C))?;
            Value::Utf8(
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| TlvError::new(at, "the string is not UTF-8"))?,
            )
        }
        0x10..=0x13 => Value::Octets(string(cursor, 1 << (element_type - 0x10))?.to_vec()),
        0x14 => Value::Null,
        0x15 => Value::Structure(container(cursor, start)?),
        0x16 => Value::Array(container(cursor, start)?),
        0x17 => Value::List(container(cursor, start)?),
        other => {
            return Err(TlvError::new(
                start,
                format!("element type 0x{other:02X} is not defined"),
            ));
        }
    };
    Ok(Some(Element { tag, value }))
}

fn tag(cursor: &mut Cursor<'_>, control: u8) -> Result<Tag, TlvError> {
    Ok(match control {
        0 => Tag::Anonymous,
        1 => Tag::Context(cursor.byte().map_err(refused(cursor.position()))?),
        2 => Tag::Common(number(cursor, 2)?),
        3 => Tag::Common(number(cursor, 4)?),
        4 => Tag::Implicit(number(cursor, 2)?),
        5 => Tag::Implicit(number(cursor, 4)?),
        wide => {
            let vendor = cursor.u16_le().map_err(refused(cursor.position()))?;
            let profile = cursor.u16_le().map_err(refused(cursor.position()))?;
            let number = number(cursor, if wide == 6 { 2 } else { 4 })?;
            Tag::FullyQualified {
                vendor,
                profile,
                number,
            }
        }
    })
}

/// A tag number of two or four bytes.
fn number(cursor: &mut Cursor<'_>, width: usize) -> Result<u32, TlvError> {
    let at = cursor.position();
    u32::try_from(unsigned(cursor, width)?)
        .map_err(|_| TlvError::new(at, "a tag number wider than four bytes"))
}

/// A length of `width` bytes, then that many bytes.
fn string<'a>(cursor: &mut Cursor<'a>, width: usize) -> Result<&'a [u8], TlvError> {
    let at = cursor.position();
    let length = usize::try_from(unsigned(cursor, width)?)
        .map_err(|_| TlvError::new(at, "the length does not fit this machine"))?;
    cursor.take(length).map_err(refused(cursor.position()))
}

fn container(cursor: &mut Cursor<'_>, opened_at: usize) -> Result<Vec<Element>, TlvError> {
    let mut members = Vec::new();
    loop {
        if cursor.is_empty() {
            return Err(TlvError::new(
                opened_at,
                "the container opened here is never closed",
            ));
        }
        match element(cursor)? {
            Some(member) => members.push(member),
            None => return Ok(members),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(element: &Element) -> Vec<u8> {
        let bytes = encode(element);
        assert_eq!(&decode(&bytes).expect("decode"), element, "{bytes:02X?}");
        bytes
    }

    #[test]
    fn every_value_kind_survives_encoding_and_decoding() {
        let members = vec![
            Element::context(0, Value::Signed(-2)),
            Element::context(1, Value::Signed(-40_000)),
            Element::context(2, Value::Signed(i64::MIN)),
            Element::context(3, Value::Unsigned(200)),
            Element::context(4, Value::Unsigned(70_000)),
            Element::context(5, Value::Unsigned(u64::MAX)),
            Element::context(6, Value::Bool(true)),
            Element::context(7, Value::Bool(false)),
            Element::context(8, Value::Float(1.5)),
            Element::context(9, Value::Double(-0.25)),
            Element::context(10, Value::Utf8("Käkkirurgi".into())),
            Element::context(11, Value::Octets(vec![0; 300])),
            Element::context(12, Value::Null),
            Element::context(
                13,
                Value::Array(vec![
                    Element::new(Tag::Anonymous, Value::Unsigned(1)),
                    Element::new(Tag::Anonymous, Value::Unsigned(2)),
                ]),
            ),
            Element::new(Tag::Common(0x1234), Value::List(vec![])),
            Element::new(Tag::Common(0x0001_0000), Value::Null),
            Element::new(Tag::Implicit(7), Value::Null),
            Element::new(
                Tag::FullyQualified {
                    vendor: 0xFFF1,
                    profile: 0xDEED,
                    number: 0x1234_5678,
                },
                Value::Utf8(String::new()),
            ),
        ];
        round_trip(&Element::new(Tag::Anonymous, Value::Structure(members)));
    }

    #[test]
    fn the_control_byte_is_type_low_and_tag_control_high() {
        let bytes = round_trip(&Element::context(5, Value::Unsigned(0x2A)));
        assert_eq!(bytes, [0x24, 0x05, 0x2A]);
        let bytes = round_trip(&Element::new(
            Tag::Anonymous,
            Value::Structure(vec![Element::context(1, Value::Bool(true))]),
        ));
        assert_eq!(bytes, [0x15, 0x29, 0x01, 0x18]);
        let bytes = round_trip(&Element::context(2, Value::Utf8("ab".into())));
        assert_eq!(bytes, [0x2C, 0x02, 0x02, b'a', b'b']);
    }

    #[test]
    fn a_container_that_never_closes_is_refused_where_it_opened() {
        let refused = decode(&[0x15, 0x24, 0x01, 0x07, 0x15, 0x24, 0x02, 0x08]);
        assert_eq!(
            refused,
            Err(TlvError::new(
                4,
                "the container opened here is never closed"
            ))
        );
    }

    #[test]
    fn an_undefined_element_type_is_refused_at_its_control_byte() {
        let refused = decode(&[0x15, 0x24, 0x01, 0x07, 0x3F, 0x02, 0x18]);
        assert_eq!(
            refused,
            Err(TlvError::new(4, "element type 0x1F is not defined"))
        );
    }

    #[test]
    fn a_length_past_the_end_is_refused_where_the_bytes_run_out() {
        let refused = decode(&[0x30, 0x01, 0x09, 0xAA, 0xBB]);
        assert_eq!(
            refused,
            Err(TlvError::new(
                3,
                "a field of 9 bytes runs past the end, 2 remain"
            ))
        );
        assert_eq!(
            decode(&[0x04, 0x01, 0x04, 0x02]),
            Err(TlvError::new(2, "bytes continue past the element"))
        );
        assert_eq!(
            decode(&[0x18]).expect_err("an end").to_string(),
            "an end-of-container opens the bytes at offset 0"
        );
    }

    #[test]
    fn a_member_is_found_by_its_context_tag() {
        let structure = Element::new(
            Tag::Anonymous,
            Value::Structure(vec![
                Element::context(0, Value::Unsigned(6)),
                Element::context(1, Value::Bool(true)),
            ]),
        );
        assert_eq!(structure.member(0).and_then(Element::as_unsigned), Some(6));
        assert_eq!(structure.member(1).and_then(Element::as_bool), Some(true));
        assert!(structure.member(2).is_none());
        assert!(structure.member(0).and_then(Element::as_bool).is_none());
    }
}
