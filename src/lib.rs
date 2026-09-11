#![forbid(unsafe_code)]

//! The Matter logic technology — a technology of `xmip-core-logic`
//! (ADR-0043, amended 2026-09-10).
//!
//! Matter's Interaction Model names an operation as an endpoint, a cluster and
//! a command, and types the arguments with the cluster's own data model in
//! TLV. An invoke request arrives as TLV; its command path becomes the
//! operation — the cluster's name or hex id as the service, the command's as
//! the name, the endpoint as a parameter — and its command fields become the
//! arguments, still TLV, under `application/vnd.matter.tlv`. A result goes
//! back as a response command carrying fields, or as a success status when it
//! carries none; a fault goes back as a general status, with the cluster's
//! own status where the cluster has one. One invocation is one command: a
//! request carrying several is refused rather than half-read.
//!
//! [`tlv`] is the codec, [`invoke`] the two messages over it. The transport
//! that carries the bytes — the session, the exchange, the protocol opcode
//! this technology names in a `matter-opcode` header — is the node's to give.

pub mod invoke;
pub mod tlv;

use invoke::{Answer, CommandData, CommandPath, InvokeRequest, InvokeResponse, Status};
use logic::{
    Arrival, Fault, Header, Invocation, Logic, LogicError, OperationName, Outcome, Reply, Request,
};
use stream::Stream;
use tlv::{Element, Value};

/// The media type of TLV bytes: a message, the arguments, a result.
pub const MEDIA_TYPE: &str = "application/vnd.matter.tlv";

/// The header naming the Interaction Model opcode a message travels under.
pub const OPCODE_HEADER: &str = "matter-opcode";
const INVOKE_REQUEST_OPCODE: &str = "8";
const INVOKE_RESPONSE_OPCODE: &str = "9";

/// The Matter technology.
pub struct Matter;

/// A cluster's id and name, and the commands it defines by id and name.
type Cluster = (u32, &'static str, &'static [(u32, &'static str)]);

/// Clusters this technology names; any other is named by its hex id.
const CLUSTERS: &[Cluster] = &[
    (
        0x0003,
        "Identify",
        &[(0x00, "Identify"), (0x40, "TriggerEffect")],
    ),
    (
        0x0004,
        "Groups",
        &[
            (0x00, "AddGroup"),
            (0x01, "ViewGroup"),
            (0x02, "GetGroupMembership"),
            (0x03, "RemoveGroup"),
            (0x04, "RemoveAllGroups"),
            (0x05, "AddGroupIfIdentifying"),
        ],
    ),
    (
        0x0006,
        "OnOff",
        &[
            (0x00, "Off"),
            (0x01, "On"),
            (0x02, "Toggle"),
            (0x40, "OffWithEffect"),
            (0x41, "OnWithRecallGlobalScene"),
            (0x42, "OnWithTimedOff"),
        ],
    ),
    (
        0x0008,
        "LevelControl",
        &[
            (0x00, "MoveToLevel"),
            (0x01, "Move"),
            (0x02, "Step"),
            (0x03, "Stop"),
            (0x04, "MoveToLevelWithOnOff"),
            (0x05, "MoveWithOnOff"),
            (0x06, "StepWithOnOff"),
            (0x07, "StopWithOnOff"),
        ],
    ),
    (
        0x003C,
        "AdministratorCommissioning",
        &[
            (0x00, "OpenCommissioningWindow"),
            (0x01, "OpenBasicCommissioningWindow"),
            (0x02, "RevokeCommissioning"),
        ],
    ),
    (
        0x0101,
        "DoorLock",
        &[
            (0x00, "LockDoor"),
            (0x01, "UnlockDoor"),
            (0x03, "UnlockWithTimeout"),
        ],
    ),
    (
        0x0102,
        "WindowCovering",
        &[
            (0x00, "UpOrOpen"),
            (0x01, "DownOrClose"),
            (0x02, "StopMotion"),
            (0x05, "GoToLiftPercentage"),
            (0x08, "GoToTiltPercentage"),
        ],
    ),
];

/// The general status codes the Interaction Model defines.
const STATUSES: &[(u8, &str)] = &[
    (0x00, "SUCCESS"),
    (0x01, "FAILURE"),
    (0x7D, "INVALID_SUBSCRIPTION"),
    (0x7E, "UNSUPPORTED_ACCESS"),
    (0x7F, "UNSUPPORTED_ENDPOINT"),
    (0x80, "INVALID_ACTION"),
    (0x81, "UNSUPPORTED_COMMAND"),
    (0x85, "INVALID_COMMAND"),
    (0x86, "UNSUPPORTED_ATTRIBUTE"),
    (0x87, "CONSTRAINT_ERROR"),
    (0x88, "UNSUPPORTED_WRITE"),
    (0x89, "RESOURCE_EXHAUSTED"),
    (0x8B, "NOT_FOUND"),
    (0x8C, "UNREPORTABLE_ATTRIBUTE"),
    (0x8D, "INVALID_DATA_TYPE"),
    (0x8F, "UNSUPPORTED_READ"),
    (0x92, "DATA_VERSION_MISMATCH"),
    (0x94, "TIMEOUT"),
    (0x9C, "BUSY"),
    (0xC3, "UNSUPPORTED_CLUSTER"),
    (0xC5, "NO_UPSTREAM_SUBSCRIPTION"),
    (0xC6, "NEEDS_TIMED_INTERACTION"),
    (0xC7, "UNSUPPORTED_EVENT"),
    (0xC8, "PATHS_EXHAUSTED"),
    (0xC9, "TIMED_REQUEST_MISMATCH"),
    (0xCA, "FAILSAFE_REQUIRED"),
    (0xCB, "INVALID_IN_STATE"),
    (0xCC, "NO_COMMAND_RESPONSE"),
];

fn cluster(id: u32) -> Option<&'static Cluster> {
    CLUSTERS.iter().find(|entry| entry.0 == id)
}

/// `0x1F` or `31` as a number.
fn parse_id(text: &str) -> Option<u32> {
    text.strip_prefix("0x").map_or_else(
        || text.parse().ok(),
        |hex| u32::from_str_radix(hex, 16).ok(),
    )
}

/// The cluster's name, or its hex id where this technology has no name.
fn cluster_name(id: u32) -> String {
    cluster(id).map_or_else(|| format!("0x{id:04X}"), |entry| entry.1.to_string())
}

fn command_name(cluster_id: u32, id: u32) -> String {
    cluster(cluster_id)
        .and_then(|entry| entry.2.iter().find(|command| command.0 == id))
        .map_or_else(|| format!("0x{id:02X}"), |command| command.1.to_string())
}

fn cluster_id(name: &str) -> Result<u32, LogicError> {
    CLUSTERS
        .iter()
        .find(|entry| entry.1 == name)
        .map(|entry| entry.0)
        .or_else(|| parse_id(name))
        .ok_or_else(|| LogicError::new(format!("{name:?} is not a cluster this node knows")))
}

fn command_id(cluster_id: u32, name: &str) -> Result<u32, LogicError> {
    cluster(cluster_id)
        .and_then(|entry| entry.2.iter().find(|command| command.1 == name))
        .map(|command| command.0)
        .or_else(|| parse_id(name))
        .ok_or_else(|| {
            LogicError::new(format!(
                "{name:?} is not a command of cluster {}",
                cluster_name(cluster_id)
            ))
        })
}

fn parameter<'a>(invocation: &'a Invocation, name: &str) -> Option<&'a str> {
    let parameter = invocation.parameters.iter().find(|p| p.name == name);
    parameter.map(|p| p.value.as_str())
}

/// The command path an invocation names: the operation and its `endpoint`.
fn path_of(invocation: &Invocation) -> Result<CommandPath, LogicError> {
    let endpoint = parameter(invocation, "endpoint")
        .ok_or_else(|| LogicError::new("the invocation names no endpoint"))?;
    let endpoint = endpoint
        .parse()
        .map_err(|_| LogicError::new(format!("endpoint {endpoint:?} is not a number")))?;
    let cluster = cluster_id(&invocation.operation.service)?;
    Ok(CommandPath {
        endpoint,
        cluster,
        command: command_id(cluster, &invocation.operation.name)?,
    })
}

fn parameters_of(command: &CommandData, request: &InvokeRequest) -> Vec<Header> {
    let mut parameters = vec![Header::new("endpoint", command.path.endpoint.to_string())];
    if let Some(command_ref) = command.command_ref {
        parameters.push(Header::new("command-ref", command_ref.to_string()));
    }
    if request.timed_request {
        parameters.push(Header::new("timed-request", "true"));
    }
    if request.suppress_response {
        parameters.push(Header::new("suppress-response", "true"));
    }
    parameters
}

/// Command fields as a Stream: the structure's bytes, or none.
fn stream_of(model: &Stream, fields: Option<&Element>) -> Stream {
    let bytes = fields.map(tlv::encode).unwrap_or_default();
    Stream::new(model.id(), bytes, Some(MEDIA_TYPE.to_string()))
}

/// A Stream as command fields: none when empty, else its TLV structure.
fn fields_of(stream: &Stream) -> Result<Option<Element>, LogicError> {
    if stream.is_empty() {
        return Ok(None);
    }
    let fields = tlv::decode(stream.bytes())
        .map_err(|error| LogicError::new(format!("the fields are not TLV: {error}")))?;
    match fields.value {
        Value::Structure(_) => Ok(Some(fields)),
        _ => Err(LogicError::new("the fields are not a TLV structure")),
    }
}

/// A status as the estate's fault: the general status by name or hex, and
/// the cluster status after a slash where there is one.
fn fault_of(status: Status) -> Fault {
    let general = STATUSES
        .iter()
        .find(|entry| entry.0 == status.general)
        .map_or_else(
            || format!("0x{:02X}", status.general),
            |entry| entry.1.to_string(),
        );
    let cluster = status
        .cluster
        .map_or_else(String::new, |cluster| format!("/0x{cluster:02X}"));
    Fault {
        message: format!("Matter status {general}{cluster}"),
        code: format!("{general}{cluster}"),
    }
}

fn status_of(fault: &Fault) -> Result<Status, LogicError> {
    let (general, cluster) = fault
        .code
        .split_once('/')
        .map_or((fault.code.as_str(), None), |(g, c)| (g, Some(c)));
    let general = STATUSES
        .iter()
        .find(|entry| entry.1 == general)
        .map(|entry| entry.0)
        .or_else(|| parse_id(general).and_then(|id| u8::try_from(id).ok()))
        .ok_or_else(|| LogicError::new(format!("{general:?} is not a Matter status")))?;
    let cluster = cluster
        .map(|text| {
            parse_id(text)
                .and_then(|id| u8::try_from(id).ok())
                .ok_or_else(|| LogicError::new(format!("{text:?} is not a cluster status")))
        })
        .transpose()?;
    Ok(Status { general, cluster })
}

fn message(id: &Stream, bytes: Vec<u8>) -> Stream {
    Stream::new(id.id(), bytes, Some(MEDIA_TYPE.to_string()))
}

fn headers(opcode: &str) -> Vec<Header> {
    vec![
        Header::new("content-type", MEDIA_TYPE),
        Header::new(OPCODE_HEADER, opcode),
    ]
}

impl Logic for Matter {
    fn technology(&self) -> &'static str {
        "matter"
    }

    fn invocation(&self, arrival: &Arrival<'_>) -> Result<Invocation, LogicError> {
        let request = InvokeRequest::decode(arrival.body.bytes())
            .map_err(|error| LogicError::new(format!("not an invoke request: {error}")))?;
        let [command] = request.commands.as_slice() else {
            return Err(LogicError::new(format!(
                "the invoke request names {} commands; one invocation is one command",
                request.commands.len()
            )));
        };
        Ok(Invocation {
            operation: OperationName::new(
                cluster_name(command.path.cluster),
                command_name(command.path.cluster, command.path.command),
            ),
            arguments: stream_of(arrival.body, command.fields.as_ref()),
            parameters: parameters_of(command, &request),
            contract: None,
        })
    }

    fn reply(&self, invocation: &Invocation, outcome: &Outcome) -> Result<Reply, LogicError> {
        let path = path_of(invocation)?;
        let command_ref = parameter(invocation, "command-ref").and_then(|r| r.parse().ok());
        let answer = match outcome {
            Outcome::Result(result) => match fields_of(result)? {
                Some(fields) => Answer::Command(CommandData {
                    path,
                    fields: Some(fields),
                    command_ref,
                }),
                None => Answer::Status {
                    path,
                    status: Status::general(Status::SUCCESS),
                    command_ref,
                },
            },
            Outcome::Fault(fault) => Answer::Status {
                path,
                status: status_of(fault)?,
                command_ref,
            },
        };
        Ok(Reply {
            headers: headers(INVOKE_RESPONSE_OPCODE),
            body: message(&invocation.arguments, InvokeResponse::of(answer).encode()),
        })
    }

    fn request(&self, invocation: &Invocation) -> Result<Request, LogicError> {
        let path = path_of(invocation)?;
        let mut request = InvokeRequest::of(CommandData {
            path,
            fields: fields_of(&invocation.arguments)?,
            command_ref: parameter(invocation, "command-ref").and_then(|r| r.parse().ok()),
        });
        request.timed_request = parameter(invocation, "timed-request") == Some("true");
        request.suppress_response = parameter(invocation, "suppress-response") == Some("true");
        Ok(Request {
            target: format!(
                "{}/{}/{}",
                path.endpoint,
                cluster_name(path.cluster),
                command_name(path.cluster, path.command)
            ),
            method: "invoke".to_string(),
            headers: headers(INVOKE_REQUEST_OPCODE),
            body: message(&invocation.arguments, request.encode()),
        })
    }

    fn outcome(&self, invocation: &Invocation, reply: &Reply) -> Result<Outcome, LogicError> {
        let response = InvokeResponse::decode(reply.body.bytes())
            .map_err(|error| LogicError::new(format!("not an invoke response: {error}")))?;
        let answer = response
            .answers
            .first()
            .ok_or_else(|| LogicError::new("the invoke response answers nothing"))?;
        Ok(match answer {
            Answer::Command(command) => {
                Outcome::Result(stream_of(&invocation.arguments, command.fields.as_ref()))
            }
            Answer::Status { status, .. } if status.is_success() => {
                Outcome::Result(stream_of(&invocation.arguments, None))
            }
            Answer::Status { status, .. } => Outcome::Fault(fault_of(*status)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlv::Tag;
    use xcore::StreamId;

    const MOVE_TO_LEVEL: CommandPath = CommandPath {
        endpoint: 1,
        cluster: 0x0008,
        command: 0x00,
    };

    fn stream(bytes: Vec<u8>) -> Stream {
        Stream::new(StreamId::new(1), bytes, Some(MEDIA_TYPE.to_string()))
    }

    fn level() -> Element {
        Element::new(
            Tag::Anonymous,
            Value::Structure(vec![Element::context(0, Value::Unsigned(128))]),
        )
    }

    fn invocation_of(body: &Stream) -> Invocation {
        let arrival = Arrival {
            target: "",
            method: "",
            headers: &[],
            body,
        };
        Matter.invocation(&arrival).expect("invocation")
    }

    #[test]
    fn an_invoke_request_becomes_endpoint_cluster_and_command_with_tlv_arguments() {
        let mut request = InvokeRequest::of(CommandData {
            path: MOVE_TO_LEVEL,
            fields: Some(level()),
            command_ref: Some(3),
        });
        request.timed_request = true;
        let invocation = invocation_of(&stream(request.encode()));
        assert_eq!(
            invocation.operation,
            OperationName::new("LevelControl", "MoveToLevel")
        );
        assert_eq!(invocation.arguments.bytes(), tlv::encode(&level()));
        assert_eq!(invocation.arguments.media_type(), Some(MEDIA_TYPE));
        assert_eq!(
            invocation.parameters,
            vec![
                Header::new("endpoint", "1"),
                Header::new("command-ref", "3"),
                Header::new("timed-request", "true"),
            ]
        );
        let unknown = InvokeRequest::of(CommandData {
            path: CommandPath {
                endpoint: 0,
                cluster: 0xFC01,
                command: 0x11,
            },
            fields: None,
            command_ref: None,
        });
        let invocation = invocation_of(&stream(unknown.encode()));
        assert_eq!(invocation.operation, OperationName::new("0xFC01", "0x11"));
        assert!(invocation.arguments.is_empty());
    }

    #[test]
    fn a_result_goes_back_as_a_command_or_a_success_and_a_fault_as_a_status() {
        let request = InvokeRequest::of(CommandData {
            path: MOVE_TO_LEVEL,
            fields: Some(level()),
            command_ref: None,
        });
        let invocation = invocation_of(&stream(request.encode()));
        let answered = |outcome: &Outcome| {
            let reply = Matter.reply(&invocation, outcome).expect("reply");
            assert!(reply.headers.contains(&Header::new(OPCODE_HEADER, "9")));
            let response = InvokeResponse::decode(reply.body.bytes()).expect("decode");
            response.answers.into_iter().next().expect("one answer")
        };
        let fields = answered(&Outcome::Result(stream(tlv::encode(&level()))));
        assert_eq!(
            fields,
            Answer::Command(CommandData {
                path: MOVE_TO_LEVEL,
                fields: Some(level()),
                command_ref: None,
            })
        );
        let success = answered(&Outcome::Result(stream(Vec::new())));
        assert!(matches!(success, Answer::Status { status, .. } if status.is_success()));
        let general = answered(&Outcome::Fault(Fault {
            code: "UNSUPPORTED_COMMAND".into(),
            message: String::new(),
        }));
        assert!(matches!(general, Answer::Status { status, .. } if status.general == 0x81));
        let specific = answered(&Outcome::Fault(Fault {
            code: "FAILURE/0x02".into(),
            message: String::new(),
        }));
        let expected = Status {
            general: Status::FAILURE,
            cluster: Some(2),
        };
        assert!(matches!(specific, Answer::Status { status, .. } if status == expected));
        let unknown = Outcome::Fault(Fault {
            code: "TEAPOT".into(),
            message: String::new(),
        });
        assert!(Matter.reply(&invocation, &unknown).is_err());
    }

    #[test]
    fn a_request_and_its_outcome_round_trip_on_the_send_side() {
        let invocation = Invocation {
            operation: OperationName::new("0x0006", "Toggle"),
            arguments: stream(Vec::new()),
            parameters: vec![Header::new("endpoint", "2")],
            contract: None,
        };
        let request = Matter.request(&invocation).expect("request");
        assert_eq!(request.target, "2/OnOff/Toggle");
        assert_eq!(request.method, "invoke");
        assert!(request.headers.contains(&Header::new(OPCODE_HEADER, "8")));
        let decoded = InvokeRequest::decode(request.body.bytes()).expect("decode");
        assert_eq!(
            decoded.commands,
            vec![CommandData {
                path: CommandPath {
                    endpoint: 2,
                    cluster: 0x0006,
                    command: 0x02,
                },
                fields: None,
                command_ref: None,
            }]
        );
        let reply_of = |answer: Answer| Reply {
            headers: Vec::new(),
            body: stream(InvokeResponse::of(answer).encode()),
        };
        let succeeded = reply_of(Answer::Status {
            path: decoded.commands[0].path,
            status: Status::general(Status::SUCCESS),
            command_ref: None,
        });
        match Matter.outcome(&invocation, &succeeded).expect("outcome") {
            Outcome::Result(result) => assert!(result.is_empty()),
            Outcome::Fault(fault) => panic!("unexpected {fault:?}"),
        }
        let answered = reply_of(Answer::Command(CommandData {
            path: decoded.commands[0].path,
            fields: Some(level()),
            command_ref: None,
        }));
        match Matter.outcome(&invocation, &answered).expect("outcome") {
            Outcome::Result(result) => assert_eq!(result.bytes(), tlv::encode(&level())),
            Outcome::Fault(fault) => panic!("unexpected {fault:?}"),
        }
        let refused = reply_of(Answer::Status {
            path: decoded.commands[0].path,
            status: Status {
                general: Status::FAILURE,
                cluster: Some(0x02),
            },
            command_ref: None,
        });
        match Matter.outcome(&invocation, &refused).expect("outcome") {
            Outcome::Fault(fault) => assert_eq!(fault.code, "FAILURE/0x02"),
            Outcome::Result(_) => panic!("expected a fault"),
        }
    }

    #[test]
    fn what_is_not_one_command_in_an_invoke_request_is_refused() {
        let garbage = stream(vec![0x15, 0x24]);
        let arrival = Arrival {
            target: "",
            method: "",
            headers: &[],
            body: &garbage,
        };
        let refused = Matter.invocation(&arrival).expect_err("garbage");
        assert!(refused.to_string().starts_with("not an invoke request"));
        let mut two = InvokeRequest::of(CommandData {
            path: MOVE_TO_LEVEL,
            fields: None,
            command_ref: None,
        });
        two.commands.push(two.commands[0].clone());
        let two = stream(two.encode());
        let arrival = Arrival {
            target: "",
            method: "",
            headers: &[],
            body: &two,
        };
        assert!(Matter.invocation(&arrival).is_err());
        let nameless = Invocation {
            operation: OperationName::new("Kettle", "Boil"),
            arguments: stream(Vec::new()),
            parameters: vec![Header::new("endpoint", "1")],
            contract: None,
        };
        assert!(Matter.request(&nameless).is_err());
        let no_endpoint = Invocation {
            parameters: Vec::new(),
            ..nameless
        };
        assert!(Matter.request(&no_endpoint).is_err());
    }
}
