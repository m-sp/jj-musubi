//! What a tailnet hub, or a client of one, sends (`musubi_transport::heartbeat`), read in pieces
//! of the sizes the input chooses, into a local side that may fail: reading never
//! panics, an answer has one encoding, frames deliver what reading them whole does, or a prefix
//! of it, and the link is read on to their end.

#![no_main]

use libfuzzer_sys::fuzz_target;
use musubi_transport::heartbeat::fuzzing;

fuzz_target!(|data: &[u8]| {
    fuzzing::link_blocking(data);
});
