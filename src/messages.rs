
use chrono::{DateTime, Utc};
use bitvec::prelude::*;
use std::fmt;


pub const CALLSIGN_MAX_BYTES: usize = 13;
pub const CALLSIGN_ALLOWED_CHARS: &str = " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ/";
#[derive(Debug)]
pub struct InvalidBitVecSizeError;

#[derive(Debug, Clone)]
pub struct CQMessage {
    pub callsign_and_location: BitVec<u8, Msb0>,  // 77 bits
    pub csprng_state: BitVec<u8, Msb0>,           // 64 bits
    pub timestamp: DateTime<Utc>,                 // 72 bits (9 bytes) when encoded
    pub signature: BitVec<u8, Msb0>,              // 256-bit BLS signature
}

impl CQMessage {
    pub fn new(timestamp: DateTime<Utc>) -> Self {
        CQMessage {
            callsign_and_location: BitVec::new(),
            csprng_state: BitVec::new(),
            timestamp,
            signature: BitVec::new(),
        }
    }

    pub fn set_callsign_and_location(&mut self, data: BitVec<u8, Msb0>) -> Result<(), InvalidBitVecSizeError> {
        if data.len() == 77 {
            self.callsign_and_location = data;
            Ok(())
        } else {
            Err(InvalidBitVecSizeError)
        }
    }

    pub fn set_csprng_state(&mut self, data: BitVec<u8, Msb0>) -> Result<(), InvalidBitVecSizeError> {
        if data.len() == 64 {
            self.csprng_state = data;
            Ok(())
        } else {
            Err(InvalidBitVecSizeError)
        }
    }

    pub fn set_signature(&mut self, data: BitVec<u8, Msb0>) -> Result<(), InvalidBitVecSizeError> {
        if data.len() == 256 {
            self.signature = data;
            Ok(())
        } else {
            Err(InvalidBitVecSizeError)
        }
    }
}

#[derive(Debug, Clone)]
pub struct RRRMessage {
    pub payload: BitVec<u8, Msb0>,                // 300 bits, used as a placeholder for signal report & RR73 payload from fox
    pub hmac: BitVec<u8, Msb0>,                   // 20-bit HMAC-like hash
    pub timestamp: DateTime<Utc>,                 // 72 bits (9 bytes) - implicit in transmission time
}

impl RRRMessage {
    pub fn new(timestamp: DateTime<Utc>) -> Self {
        RRRMessage {
            payload: BitVec::new(),
            hmac: BitVec::new(),
            timestamp,
        }
    }

    pub fn set_payload(&mut self, data: BitVec<u8, Msb0>) -> Result<(), InvalidBitVecSizeError> {
        if data.len() == 300 { // Ensures RRR payload is exactly 300 bits
            self.payload = data;
            Ok(())
        } else {
            Err(InvalidBitVecSizeError)
        }
    }

    pub fn set_hmac(&mut self, data: BitVec<u8, Msb0>) -> Result<(), InvalidBitVecSizeError> {
        if data.len() == 20 { // Ensures HMAC-like hash is exactly 20 bits
            self.hmac = data;
            Ok(())
        } else {
            Err(InvalidBitVecSizeError)
        }
    }
}

impl fmt::Display for RRRMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: <... 300 signal report/RR73 bits ...> + {} hash (20 bits) -- (320 bits total, before FEC)",
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            format_bitvec(&self.hmac)
        )
    }
}

impl fmt::Display for CQMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: <... 77 callsign_and_location bits ...> + {} CSPRNG state (64 bits) + {} BLS signature (256 bits) -- (397 bits total, before FEC)",
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            format_bitvec(&self.csprng_state),
            format_bitvec(&self.signature)
        )
    }
}

#[derive(Debug, Clone)]
pub enum RadioMessage {
    CQ(CQMessage),
    RRR(RRRMessage),
}

impl RadioMessage {
    pub fn timestamp(&self) -> &DateTime<Utc> {
        match self {
            RadioMessage::CQ(msg) => &msg.timestamp,
            RadioMessage::RRR(msg) => &msg.timestamp,
        }
    }
}

/// Formats a BitVec into a string of '0's and '1's.
///
/// This function takes a reference to any BitVec and returns a String
/// representation of its bits, with '0' for unset bits and '1' for set bits.
///
/// # Arguments
///
/// * `bits` - A reference to a BitVec to be formatted.
///
/// # Returns
///
/// A String containing '0's and '1's representing the input BitVec.
///
pub fn format_bitvec<T: BitStore>(bits: &BitVec<T, Msb0>) -> String {
    bits.iter().map(|b| if *b { '1' } else { '0' }).collect()
}
