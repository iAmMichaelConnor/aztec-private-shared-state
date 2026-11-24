//! The HTTPS plumbing the node and the orchestrator share: the API's TLS
//! set-up (`tls`), the bounded listener both serve on (`listen`), the JSON
//! answers in the one error shape and the handlers' small parsers
//! (`respond`), and the mutual-TLS JSON client of the node API (`client`),
//! which the orchestrator's node leg and the tests use; and the operator's
//! admin socket (`admin`: bind, serve, call, the path checks). Each binary
//! keeps its own routes, its own limits and its own admin commands.

pub mod admin;
pub mod client;
pub mod listen;
pub mod respond;
pub mod tls;
