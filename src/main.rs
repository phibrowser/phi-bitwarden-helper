// Phi Bitwarden Helper
// Copyright (C) 2026 Phinomenon Inc.
// SPDX-License-Identifier: GPL-3.0-only
//
// Out-of-process Bitwarden vault helper for Phi Browser, written in native Rust
// so it can link the Bitwarden SDK (bitwarden/sdk-internal, GPL-3.0) directly —
// no UniFFI, no xcframework, no macOS-slice problem. Phi's Swift app spawns this
// binary at <App>.app/Contents/Helpers/PhiBitwardenHelper with one end of a
// socketpair(2) as fd 0 and talks framed JSON over it — there is no filesystem
// socket for another process to connect to or impersonate, and the kernel pins
// both peer identities. The app links none of this and stays Apache-2.0. See
// README.md for the process boundary and build instructions.

mod engine;
mod protocol;

#[cfg(feature = "bitwarden-sdk")]
mod bitwarden_engine;

use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use engine::Engine;

extern "C" {
    fn dup(fd: c_int) -> c_int;
    fn dup2(from: c_int, to: c_int) -> c_int;
}

fn main() {
    let stream = take_ipc_stream();
    let engine = build_engine();
    if let Err(e) = protocol::run(stream, engine) {
        eprintln!("PhiBitwardenHelper: server error: {e}");
        std::process::exit(1);
    }
}

/// Claims the socketpair end the spawning Phi process passed as fd 0, then
/// points fd 0 at /dev/null so no dependency can accidentally read from or
/// write to the vault channel.
fn take_ipc_stream() -> UnixStream {
    let raw = unsafe { dup(0) };
    if raw < 0 {
        eprintln!("PhiBitwardenHelper: cannot dup fd 0");
        std::process::exit(2);
    }
    let stream = unsafe { UnixStream::from_raw_fd(raw) };
    if stream.peer_addr().is_err() {
        eprintln!(
            "PhiBitwardenHelper: fd 0 is not a socket — this helper is spawned by \
             Phi with a socketpair on stdin, not run directly"
        );
        std::process::exit(2);
    }
    if let Ok(devnull) = std::fs::File::open("/dev/null") {
        unsafe {
            dup2(devnull.as_raw_fd(), 0);
        }
    }
    stream
}

#[cfg(feature = "bitwarden-sdk")]
fn build_engine() -> Arc<dyn Engine> {
    Arc::new(bitwarden_engine::SdkEngine::new())
}

#[cfg(not(feature = "bitwarden-sdk"))]
fn build_engine() -> Arc<dyn Engine> {
    Arc::new(engine::StubEngine::new())
}
