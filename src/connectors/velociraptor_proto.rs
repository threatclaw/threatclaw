//! Generated tonic stubs for the Velociraptor v0.76 gRPC API.
//!
//! The `.proto` tree lives under `proto/velociraptor/` and is compiled
//! by `build.rs` via `tonic-build` into `$OUT_DIR`. All Velociraptor
//! protos declare `package proto;` so the generated Rust namespace
//! collapses to a single `proto` module — we re-export it here under
//! an explicit name so call sites can write `velociraptor_proto::...`.
//!
//! Only the `api_client` service + its message types are used by the
//! connector. The other nested modules (hunt, artifact, flow...) are
//! available if we ever need them.
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::enum_variant_names)]
#![allow(unused_qualifications)]

pub mod google {
    pub mod api {
        tonic::include_proto!("google.api");
    }
}

tonic::include_proto!("proto");
