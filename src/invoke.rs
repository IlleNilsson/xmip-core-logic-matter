//! The Interaction Model's invoke action: a request names an endpoint, a
//! cluster and a command and carries the command's fields; a response carries
//! either a response command with its fields or a status. Both are TLV
//! structures whose members carry context tags, exactly as the specification
//! lays them out — this file knows those tags, and [`crate::tlv`] the bytes.

use crate::tlv::{self, Element, Tag, TlvError, Value};

/// The Interaction Model revision these messages are written at.
pub const INTERACTION_MODEL_REVISION: u8 = 11;

/// Which command on which cluster on which endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandPath {
    pub endpoint: u16,
    pub cluster: u32,
    pub command: u32,
}

/// A command with its fields, on the way in or as a response command on the
/// way back. `fields` is the command's structure when the command has fields.
#[derive(Clone, Debug, PartialEq)]
pub struct CommandData {
    pub path: CommandPath,
    pub fields: Option<Element>,
    pub command_ref: Option<u16>,
}

/// A general status, and a cluster's own where the cluster has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub general: u8,
    pub cluster: Option<u8>,
}

impl Status {
    /// The general status of a command that did what it was asked.
    pub const SUCCESS: u8 = 0x00;
    /// The general status a cluster-specific status travels under.
    pub const FAILURE: u8 = 0x01;

    /// A general status with no cluster status.
    #[must_use]
    pub const fn general(code: u8) -> Self {
        Self {
            general: code,
            cluster: None,
        }
    }

    /// Whether the command succeeded.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.general == Self::SUCCESS
    }
}

/// What a command was answered with.
#[derive(Clone, Debug, PartialEq)]
pub enum Answer {
    Command(CommandData),
    Status {
        path: CommandPath,
        status: Status,
        command_ref: Option<u16>,
    },
}

/// An invoke request message.
#[derive(Clone, Debug, PartialEq)]
pub struct InvokeRequest {
    pub suppress_response: bool,
    pub timed_request: bool,
    pub commands: Vec<CommandData>,
    pub revision: u8,
}

/// An invoke response message.
#[derive(Clone, Debug, PartialEq)]
pub struct InvokeResponse {
    pub suppress_response: bool,
    pub answers: Vec<Answer>,
    pub revision: u8,
}

/// Why bytes are not the invoke message they were read as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvokeError {
    /// The bytes are not TLV.
    Tlv(TlvError),
    /// The TLV is not laid out as the message requires.
    Shape(String),
}

impl core::fmt::Display for InvokeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InvokeError::Tlv(error) => write!(f, "not TLV: {error}"),
            InvokeError::Shape(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for InvokeError {}

impl From<TlvError> for InvokeError {
    fn from(error: TlvError) -> Self {
        InvokeError::Tlv(error)
    }
}

fn shape(reason: impl Into<String>) -> InvokeError {
    InvokeError::Shape(reason.into())
}

const REVISION_TAG: u8 = 0xFF;

impl InvokeRequest {
    /// One command, answered, untimed.
    #[must_use]
    pub fn of(command: CommandData) -> Self {
        Self {
            suppress_response: false,
            timed_request: false,
            commands: vec![command],
            revision: INTERACTION_MODEL_REVISION,
        }
    }

    /// The message as bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let commands = self
            .commands
            .iter()
            .map(|command| Element::new(Tag::Anonymous, command_data(command)))
            .collect();
        tlv::encode(&Element::new(
            Tag::Anonymous,
            Value::Structure(vec![
                Element::context(0, Value::Bool(self.suppress_response)),
                Element::context(1, Value::Bool(self.timed_request)),
                Element::context(2, Value::Array(commands)),
                Element::context(REVISION_TAG, Value::Unsigned(u64::from(self.revision))),
            ]),
        ))
    }

    /// The message the bytes hold.
    ///
    /// # Errors
    /// The bytes are not TLV, or not an invoke request.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvokeError> {
        let message = tlv::decode(bytes)?;
        let commands = message
            .member(2)
            .and_then(Element::members)
            .ok_or_else(|| shape("the invoke request has no InvokeRequests"))?
            .iter()
            .map(read_command_data)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            suppress_response: flag(&message, 0),
            timed_request: flag(&message, 1),
            commands,
            revision: revision(&message)?,
        })
    }
}

impl InvokeResponse {
    /// One answer.
    #[must_use]
    pub fn of(answer: Answer) -> Self {
        Self {
            suppress_response: false,
            answers: vec![answer],
            revision: INTERACTION_MODEL_REVISION,
        }
    }

    /// The message as bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let answers = self
            .answers
            .iter()
            .map(|answer| Element::new(Tag::Anonymous, answer_value(answer)))
            .collect();
        tlv::encode(&Element::new(
            Tag::Anonymous,
            Value::Structure(vec![
                Element::context(0, Value::Bool(self.suppress_response)),
                Element::context(1, Value::Array(answers)),
                Element::context(REVISION_TAG, Value::Unsigned(u64::from(self.revision))),
            ]),
        ))
    }

    /// The message the bytes hold.
    ///
    /// # Errors
    /// The bytes are not TLV, or not an invoke response.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvokeError> {
        let message = tlv::decode(bytes)?;
        let answers = message
            .member(1)
            .and_then(Element::members)
            .ok_or_else(|| shape("the invoke response has no InvokeResponses"))?
            .iter()
            .map(read_answer)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            suppress_response: flag(&message, 0),
            answers,
            revision: revision(&message)?,
        })
    }
}

fn flag(message: &Element, tag: u8) -> bool {
    message
        .member(tag)
        .and_then(Element::as_bool)
        .unwrap_or(false)
}

fn revision(message: &Element) -> Result<u8, InvokeError> {
    let revision = message
        .member(REVISION_TAG)
        .and_then(Element::as_unsigned)
        .ok_or_else(|| shape("the message carries no InteractionModelRevision"))?;
    u8::try_from(revision).map_err(|_| shape(format!("revision {revision} is not a byte")))
}

fn command_path(path: CommandPath) -> Value {
    Value::List(vec![
        Element::context(0, Value::Unsigned(u64::from(path.endpoint))),
        Element::context(1, Value::Unsigned(u64::from(path.cluster))),
        Element::context(2, Value::Unsigned(u64::from(path.command))),
    ])
}

fn command_data(command: &CommandData) -> Value {
    let mut members = vec![Element::context(0, command_path(command.path))];
    if let Some(fields) = &command.fields {
        members.push(Element::context(1, fields.value.clone()));
    }
    if let Some(command_ref) = command.command_ref {
        members.push(Element::context(2, Value::Unsigned(u64::from(command_ref))));
    }
    Value::Structure(members)
}

fn answer_value(answer: &Answer) -> Value {
    match answer {
        Answer::Command(command) => {
            Value::Structure(vec![Element::context(0, command_data(command))])
        }
        Answer::Status {
            path,
            status,
            command_ref,
        } => {
            let mut status_ib = vec![Element::context(
                0,
                Value::Unsigned(u64::from(status.general)),
            )];
            if let Some(cluster) = status.cluster {
                status_ib.push(Element::context(1, Value::Unsigned(u64::from(cluster))));
            }
            let mut members = vec![
                Element::context(0, command_path(*path)),
                Element::context(1, Value::Structure(status_ib)),
            ];
            if let Some(command_ref) = command_ref {
                members.push(Element::context(
                    2,
                    Value::Unsigned(u64::from(*command_ref)),
                ));
            }
            Value::Structure(vec![Element::context(1, Value::Structure(members))])
        }
    }
}

fn unsigned<T: TryFrom<u64>>(parent: &Element, tag: u8, what: &str) -> Result<T, InvokeError> {
    let value = parent
        .member(tag)
        .and_then(Element::as_unsigned)
        .ok_or_else(|| shape(format!("{what} is missing or not an unsigned integer")))?;
    T::try_from(value).map_err(|_| shape(format!("{what} {value} is out of range")))
}

fn optional_ref(parent: &Element) -> Result<Option<u16>, InvokeError> {
    parent
        .member(2)
        .map(|_| unsigned(parent, 2, "CommandRef"))
        .transpose()
}

fn read_command_path(parent: &Element) -> Result<CommandPath, InvokeError> {
    let path = parent
        .member(0)
        .ok_or_else(|| shape("a CommandPath is missing"))?;
    Ok(CommandPath {
        endpoint: unsigned(path, 0, "EndpointId")?,
        cluster: unsigned(path, 1, "ClusterId")?,
        command: unsigned(path, 2, "CommandId")?,
    })
}

fn read_command_data(element: &Element) -> Result<CommandData, InvokeError> {
    let fields = match element.member(1) {
        Some(fields) if matches!(fields.value, Value::Structure(_)) => {
            Some(Element::new(Tag::Anonymous, fields.value.clone()))
        }
        Some(_) => return Err(shape("CommandFields is not a structure")),
        None => None,
    };
    Ok(CommandData {
        path: read_command_path(element)?,
        fields,
        command_ref: optional_ref(element)?,
    })
}

fn read_answer(element: &Element) -> Result<Answer, InvokeError> {
    if let Some(command) = element.member(0) {
        return Ok(Answer::Command(read_command_data(command)?));
    }
    let status_ib = element
        .member(1)
        .ok_or_else(|| shape("an InvokeResponse is neither a Command nor a Status"))?;
    let status = status_ib
        .member(1)
        .ok_or_else(|| shape("a CommandStatus has no Status"))?;
    Ok(Answer::Status {
        path: read_command_path(status_ib)?,
        status: Status {
            general: unsigned(status, 0, "Status")?,
            cluster: status
                .member(1)
                .map(|_| unsigned(status, 1, "ClusterStatus"))
                .transpose()?,
        },
        command_ref: optional_ref(status_ib)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOGGLE: CommandPath = CommandPath {
        endpoint: 1,
        cluster: 0x0006,
        command: 0x02,
    };

    fn level_fields() -> Element {
        Element::new(
            Tag::Anonymous,
            Value::Structure(vec![
                Element::context(0, Value::Unsigned(128)),
                Element::context(1, Value::Unsigned(10)),
            ]),
        )
    }

    #[test]
    fn a_request_built_encoded_and_decoded_is_equal() {
        let request = InvokeRequest {
            suppress_response: false,
            timed_request: true,
            commands: vec![CommandData {
                path: CommandPath {
                    endpoint: 2,
                    cluster: 0x0008,
                    command: 0x00,
                },
                fields: Some(level_fields()),
                command_ref: Some(7),
            }],
            revision: INTERACTION_MODEL_REVISION,
        };
        let bytes = request.encode();
        assert_eq!(InvokeRequest::decode(&bytes).expect("decode"), request);
        let bare = InvokeRequest::of(CommandData {
            path: TOGGLE,
            fields: None,
            command_ref: None,
        });
        assert_eq!(InvokeRequest::decode(&bare.encode()).expect("decode"), bare);
    }

    #[test]
    fn a_request_is_laid_out_with_the_specifications_tags() {
        let bytes = InvokeRequest::of(CommandData {
            path: TOGGLE,
            fields: None,
            command_ref: None,
        })
        .encode();
        let expected: &[u8] = &[
            0x15, 0x28, 0x00, 0x28, 0x01, 0x36, 0x02, 0x15, 0x37, 0x00, 0x24, 0x00, 0x01, 0x24,
            0x01, 0x06, 0x24, 0x02, 0x02, 0x18, 0x18, 0x18, 0x24, 0xFF, 0x0B, 0x18,
        ];
        assert_eq!(bytes, expected, "{bytes:02X?}");
    }

    #[test]
    fn a_status_response_and_a_command_response_round_trip() {
        let status = InvokeResponse::of(Answer::Status {
            path: TOGGLE,
            status: Status {
                general: 0x81,
                cluster: Some(0x02),
            },
            command_ref: Some(1),
        });
        assert_eq!(
            InvokeResponse::decode(&status.encode()).expect("decode"),
            status
        );
        let command = InvokeResponse::of(Answer::Command(CommandData {
            path: TOGGLE,
            fields: Some(level_fields()),
            command_ref: None,
        }));
        assert_eq!(
            InvokeResponse::decode(&command.encode()).expect("decode"),
            command
        );
    }

    #[test]
    fn what_is_not_an_invoke_message_is_refused_with_the_reason() {
        assert!(matches!(
            InvokeRequest::decode(&[0x15]),
            Err(InvokeError::Tlv(_))
        ));
        assert!(matches!(
            InvokeResponse::decode(&[0x04, 0x01]),
            Err(InvokeError::Shape(_))
        ));
        let no_path = tlv::encode(&Element::new(
            Tag::Anonymous,
            Value::Structure(vec![
                Element::context(
                    2,
                    Value::Array(vec![Element::new(Tag::Anonymous, Value::Structure(vec![]))]),
                ),
                Element::context(REVISION_TAG, Value::Unsigned(11)),
            ]),
        ));
        assert_eq!(
            InvokeRequest::decode(&no_path),
            Err(InvokeError::Shape("a CommandPath is missing".into()))
        );
        assert_eq!(
            InvokeError::Tlv(TlvError {
                offset: 0,
                reason: "x".into()
            })
            .to_string(),
            "not TLV: x at offset 0"
        );
    }
}
