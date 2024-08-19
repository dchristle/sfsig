use std::collections::BTreeMap;
use std::fmt;
use std::ops::{Bound, Mul};
use std::string::ToString;
use std::time::Instant;
use ark_bn254::{Bn254, G1Affine, G2Affine, Fr as ScalarField};
use ark_bn254::g2::Config;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::Affine;
use ark_ff::{BigInteger, PrimeField};
use ark_std::UniformRand;
use sha2::{Digest, Sha256};
use ark_serialize;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bitvec::prelude::*;


use blake3;
use chrono::{DateTime, Timelike, Utc, Duration, Datelike, TimeZone};
use clap::Parser;
use rand::Rng;

const CALLSIGN_MAX_BYTES: usize = 13;
const CALLSIGN_ALLOWED_CHARS: &str = " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ/";

// Must be at least 8 + 13 + 9 bytes for the state + callsign + timestamp, respectively
const INTERNAL_HASH_INPUT_SIZE_BYTES: usize = 32;
const MAX_CACHE_SIZE: usize = 2 * 1024 * 1024 * 8 / 64;

#[allow(dead_code)]
struct SuperfoxCsprng {
    seed: u64,
    csprng_epoch: DateTime<Utc>,
    callsign: [u8; CALLSIGN_MAX_BYTES],
    cache: BTreeMap<DateTime<Utc>, u64>
}


impl SuperfoxCsprng {
    fn new(seed: u64, callsign: &str, csprng_epoch: &DateTime<Utc>) -> Result<Self, String> {
        // Process callsign similar to ihashcall
        if callsign.len() > CALLSIGN_MAX_BYTES {
            return Err(format!("Callsign must be no longer than {} characters", CALLSIGN_MAX_BYTES));
        }
        let callsign = callsign.to_uppercase();
        let padded_call = format!("{:13}", callsign); // Right-pad with spaces to 13 chars
        if !padded_call.chars().all(|c| CALLSIGN_ALLOWED_CHARS.find(c).is_some() ) {
            return Err("Callsign must only use allowed characters".to_string());
        }

        let validated_csprng_epoch: &DateTime<Utc> = Self::validate_15_second_interval(csprng_epoch)?;

        let padded_callsign_bytes = Self::generate_padded_callsign_bytes(callsign);

        // Create a cache-like data structure to support efficient hash lookup with bounded memory
        let mut cache: BTreeMap<DateTime<Utc>, u64> = BTreeMap::new();

        let now_utc = Utc::now();
        let floored_now_utc = Self::floor_to_15_seconds(&now_utc);
        let total_duration = validated_csprng_epoch.signed_duration_since(floored_now_utc);
        let total_intervals = (total_duration.num_seconds() / 15) as usize;

        // k is the smallest power-of-two to keep the # of cached hashes fewer than MAX_CACHE_SIZE
        let k = (total_intervals as f64 / MAX_CACHE_SIZE as f64).log2().ceil() as u32;
        let cache_interval = 2_u64.pow(k);
        let est_total_cached_values = total_intervals as u64/cache_interval;
        println!("k is {} and cache_interval is {}, implying {} cached values", k.clone(), cache_interval.clone(), est_total_cached_values);

        let measure_timing_start = Instant::now();

        let mut current_state: u64 = seed;
        let mut current_time = validated_csprng_epoch.clone();
        println!("Validated epoch is {}, start time is {}", current_time.clone(), floored_now_utc.clone());
        println!("Populating cache...");

        // Compute CSPRNG outputs for all 15-second intervals between now & csprng_epoch
        //
        // A small change would make it possible to store only a fraction of these CSPRNG states
        let mut count = 0;
        while current_time > floored_now_utc {  // Changed condition here
            match Self::next(current_state, &padded_callsign_bytes, &current_time) {
                Ok(hash) => {
                    // Uncomment this to store only a fraction of CSPRNG states (currently bugged)
                    // if count % cache_interval == 0 {
                    //     cache.insert(current_time, hash);
                    // }
                    cache.insert(current_time, hash);
                    current_state = hash; // Use current hash output as state input to next iteration
                    count += 1;
                },
                Err(e) => {
                    println!("Error occurred at current_time {}: {}", current_time, e);
                    break;
                }
            }
            current_time -= Duration::seconds(15);
        }

        println!("Finished computing {} hash values and caching {} entries in {} seconds.",
                 count, cache.len(), measure_timing_start.elapsed().as_secs_f32());

        Ok(SuperfoxCsprng {
            seed,
            csprng_epoch: *validated_csprng_epoch,
            callsign: padded_callsign_bytes,
            cache: cache
        })
    }

    fn generate_padded_callsign_bytes(callsign: String) -> [u8; 13] {
        let mut padded_callsign_bytes: [u8; CALLSIGN_MAX_BYTES] = [0u8; CALLSIGN_MAX_BYTES];
        for (i, &byte) in callsign.as_bytes().iter().take(CALLSIGN_MAX_BYTES).enumerate() {
            padded_callsign_bytes[i] = byte;
        }
        padded_callsign_bytes
    }

    fn floor_to_15_seconds(time: &DateTime<Utc>) -> DateTime<Utc> {
        if time.second() % 15 == 0 && time.nanosecond() == 0 {
            return time.clone();
        }

        // Create a copy floored to the minute
        let floored_to_minute = time
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap();

        let seconds_diff = time.signed_duration_since(floored_to_minute).num_seconds();
        let intervals = (seconds_diff as u32) / 15;
        floored_to_minute + Duration::seconds((intervals * 15) as i64)
    }

    fn validate_15_second_interval(time: &DateTime<Utc>) -> Result<&DateTime<Utc>, String> {
        match time.second() {
            0 | 15 | 30 | 45 => Ok(time),
            _ => Err("Time must be at a 15-second interval".to_string()),
        }
    }

    pub fn next(previous_state: u64, &callsign: &[u8; CALLSIGN_MAX_BYTES], current_time: &DateTime<Utc>) -> Result<u64, String> {
        let valid_time = Self::validate_15_second_interval(&current_time)?;

        let mut input = [0u8; INTERNAL_HASH_INPUT_SIZE_BYTES];

        // Populate input array
        input[0..8].copy_from_slice(&previous_state.to_be_bytes());
        input[8..21].copy_from_slice(&callsign);
        input[21..25].copy_from_slice(&valid_time.year().to_be_bytes());
        input[25..26].copy_from_slice(&[valid_time.month() as u8]);
        input[26..27].copy_from_slice(&[valid_time.day() as u8]);
        input[28..29].copy_from_slice(&[valid_time.hour() as u8]);
        input[29..30].copy_from_slice(&[valid_time.minute() as u8]);
        input[30..31].copy_from_slice(&[valid_time.second() as u8]);

        let hash = blake3::hash(&input);
        let new_state = u64::from_be_bytes(hash.as_bytes()[0..8].try_into().unwrap());
        let xor_bits = u64::from_be_bytes(hash.as_bytes()[8..16].try_into().unwrap());

        Ok(new_state ^ xor_bits)
    }

    pub fn advance_multiple_steps(initial_state: u64, steps: u64, callsign: &[u8; CALLSIGN_MAX_BYTES], end_time: &DateTime<Utc>) -> Result<u64, String> {
        let mut current_state = initial_state;
        let mut current_time = *end_time;

        for _ in 0..steps {
            current_time = current_time - Duration::seconds(15);
            current_state = Self::next(current_state, callsign, &current_time)?;
        }

        Ok(current_state)
    }

    // pub fn get_rand(&self, current_time: &DateTime<Utc>) -> Result<u64, String> {
    //     let floored_time = Self::floor_to_15_seconds(current_time);
    //
    //     if floored_time > self.csprng_epoch {
    //         return Err("Cannot generate values for times after the CSPRNG epoch".to_string());
    //     }
    //
    //     // Find the nearest future cached time
    //     let (cached_time, cached_state) = self.cache
    //         .range(floored_time..)
    //         .next()
    //         .ok_or("No suitable cached value found")?;
    //
    //     let mut current_state = *cached_state;
    //     let mut current_it_time = *cached_time;
    //
    //     // Compute hashes from the cached time to the desired time
    //     while current_it_time > floored_time {
    //         current_it_time -= Duration::seconds(15);
    //         current_state = Self::next(current_state, &self.callsign, &current_it_time)?;
    //     }
    //
    //     Ok(current_state)
    // }
    pub fn get_rand(&self, current_time: &DateTime<Utc>) -> Result<u64, String> {
        let floored_time = Self::floor_to_15_seconds(current_time);

        if floored_time > self.csprng_epoch {
            return Err("Cannot generate values for times after the CSPRNG epoch".to_string());
        }

        // First, try to get an exact match
        if let Some(value) = self.cache.get(&floored_time) {
            return Ok(*value);
        }
        println!("get_rand did *not* find an exact match for time {}", floored_time.clone());

        // If no exact match, find the nearest future cached time
        let (cached_time, cached_state) = self.cache
            .range((Bound::Excluded(floored_time), Bound::Unbounded))
            .next()
            .ok_or("No suitable cached value found")?;

        let mut current_state = *cached_state;
        let mut current_it_time = *cached_time;

        // Compute hashes from the cached time to the desired time
        while current_it_time > floored_time {
            current_state = Self::next(current_state, &self.callsign, &current_it_time)?;
            current_it_time -= Duration::seconds(15);
        }

        Ok(current_state)
    }
}


#[derive(Debug)]
pub struct InvalidBitVecSizeError;

#[derive(Debug, Clone)]
pub struct CQMessage {
    callsign_and_location: BitVec<u8, Msb0>,  // 77 bits
    csprng_state: BitVec<u8, Msb0>,           // 64 bits
    timestamp: DateTime<Utc>,                 // 72 bits (9 bytes) when encoded
    signature: BitVec<u8, Msb0>,              // 256-bit BLS signature
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
    payload: BitVec<u8, Msb0>,                // 300 bits, used as a placeholder for signal report & RR73 payload from fox
    hmac: BitVec<u8, Msb0>,                   // 20-bit HMAC-like hash
    timestamp: DateTime<Utc>,                 // 72 bits (9 bytes) - implicit in transmission time
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

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Probability of a Hound failing to decode a message sent by the Fox
    #[arg(short, long, default_value_t = 0.2)]
    p_loss: f32,

    /// Callsign of the Fox station
    #[arg(short, long, default_value = "N5J")]
    callsign: String,

    /// Number of 15 second time periods to simulate
    #[arg(short, long, default_value_t = 90)]
    num_periods_to_simulate: usize,

    /// Number of CQ messages a Fox should send at the end of a session
    #[arg(short, long, default_value_t = 3)]
    num_final_cq_messages: usize,
}



fn main() {
    let cli = Cli::parse();

    // Use the parsed values in your simulation
    let p_loss = cli.p_loss;
    let callsign = cli.callsign;
    let num_periods_to_simulate = cli.num_periods_to_simulate;
    let num_final_cq_messages = cli.num_final_cq_messages;

    // Your existing code here, using these variables instead of hardcoded values
    println!("Simulation parameters:");
    println!("P(loss): {}", p_loss);
    println!("Callsign: {}", callsign);
    println!("Number of periods to simulate: {} ({:.2}% minutes)", num_periods_to_simulate, (num_periods_to_simulate as f64 - 1.0)*0.25);
    println!("Number of final CQ messages: {}", num_final_cq_messages);
    println!();


    let mut rng = rand::thread_rng();

    // Generate private key
    let private_key: ScalarField = ScalarField::rand(&mut rng);

    // Compute public key in G2, so that we can use the smaller G1 for the signature
    let public_key: Affine<Config> = G2Affine::generator().mul(private_key).into_affine();

    // Test message to sign
    let message = b"Hello, world!";

    // Hash the message to G1
    let hashed_message = hash_message_to_g1(message);

    // Sign the message (signature in G1)
    let signature = hashed_message.mul(private_key).into_affine();

    // Print results
    println!("Private key: 0x{}", hex::encode(private_key.clone().into_bigint().to_bytes_le()));
    println!("Private key size: {} bits", private_key.clone().into_bigint().to_bytes_le().len() * 8);

    let mut pk_bytes = Vec::new();
    public_key.serialize_compressed(&mut pk_bytes).unwrap();
    let pk_bits = pk_bytes.clone().len() * 8;
    println!("Public key (G2): 0x{}", hex::encode(pk_bytes.clone()));
    println!("Public key size: {} bits", pk_bits.clone());

    println!("Message (arbitrary size): {:?}", std::str::from_utf8(message).unwrap());

    let mut sig_bytes = Vec::new();
    signature.serialize_compressed(&mut sig_bytes).unwrap();
    let sig_bits = sig_bytes.clone().len() * 8;
    println!("Signature (G1): 0x{}", hex::encode(sig_bytes));
    println!("Signature size: {} bits", sig_bits);

    // Verify the signature
    let lhs = Bn254::pairing(signature, G2Affine::generator());
    let rhs = Bn254::pairing(hashed_message, public_key);

    println!("Signature valid: {}", lhs == rhs);

    // Initialize the CSPRNG
    // - state: a randomly generated 64 bits
    // - csprng_epoch: a UTC time truncated to the current 15-second UTC interval
    // - callsign: a string representing the DXpedition callsign
    let seed = 0x0123456789ABCDEF; // hardcoded for demo
    let csprng_epoch = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let callsign = "N5J".to_string();

    let csprng = SuperfoxCsprng::new(seed, &callsign, &csprng_epoch).unwrap();


    // Simulate DXpedition transmissions:
    //
    // 1) Every 5 minutes, emit a 'CQ' message containing the callsign, the current time's
    //    revealable CSPRNG u64 state, and a 256-bit signature
    // 2) One period is 15 seconds. Foxes only transmit on :00 and :30. Responses on :15 and
    //    :45 aren't simulated.
    // 3) Fox replies with signal reports/RR73's

    let next_minute = (Utc::now() + Duration::minutes(1))
        .with_second(0).unwrap()
        .with_nanosecond(0).unwrap();

    println!();
    println!("Starting simulation of {} periods, starting from coalesced UTC time {}.", num_periods_to_simulate.clone(), next_minute.clone());
    println!();

    let mut messages_transmitted: Vec<RadioMessage> = Vec::with_capacity(num_periods_to_simulate);

    for i in 0..num_periods_to_simulate {
        let current_time = next_minute + Duration::seconds(i as i64 * 15);

        if (current_time.minute() % 5 == 0 && current_time.second() == 0) || (num_periods_to_simulate - i) <= num_final_cq_messages {
            // Transmit special CQ message containing:
            //   -77-bit callsign/grid message
            //   -64-bit CSPRNG state
            //   -256-bit BLS signature of the prior (77 + 64) bits
            //
            // The timestamp is implicit in the transmission time, so while it's not part of the
            // transmitted bits, we can still use it in our computations.
            let mut cq_message = CQMessage::new(current_time);

            // Make dummy callsign/grid bits
            let message_string = pad_and_encode_message(("CQ ".to_string() + &callsign.clone()).as_str());
            let cq_message_as_77_bits: BitVec<u8, Msb0> = bytes_to_bitvec(&pack80(&message_string), 77);
            cq_message.set_callsign_and_location(cq_message_as_77_bits.clone()).unwrap();

            // Find the CSPRNG state that we reveal in this message
            let csprng_state_to_reveal = csprng.get_rand(&current_time).unwrap();
            let csprng_state_bits = u64_to_bitvec(csprng_state_to_reveal);
            cq_message.set_csprng_state(csprng_state_bits.clone()).unwrap();

            // Get the timestamp encoded as 72 bits from the current time
            let timestamp_bits = bytes_to_bitvec(&timestamp_as_bytes(&cq_message.timestamp), 72);

            // Compute the 256-bit signature from the concatenated (77 + 64) bits + 72 implicit timestamp bits
            let mut concatenated_message_bits: BitVec<u8, Msb0> = cq_message.callsign_and_location.clone();
            concatenated_message_bits.extend_from_bitslice(&cq_message.csprng_state);
            concatenated_message_bits.extend_from_bitslice(&timestamp_bits);

            let message_signature = generate_bls_signature(&concatenated_message_bits, &private_key);
            let mut message_signature_bytes = Vec::new();
            message_signature.serialize_compressed(&mut message_signature_bytes).unwrap();
            let message_signature_bits = bytes_to_bitvec(&message_signature_bytes, 256);
            cq_message.set_signature(message_signature_bits).unwrap();

            // Transmit the message
            println!("{}", cq_message.clone());
            messages_transmitted.push(RadioMessage::CQ(cq_message));
        }

        if (current_time.minute() % 5 != 0) && (current_time.second() == 0 || current_time.second() == 30) && !((num_periods_to_simulate - i) <= num_final_cq_messages) {
            // Time to transmit a signal report/RR73-containing message
            let mut rrr_message = RRRMessage::new(current_time);

            // Generate 300 random bits representing the signal reports/RR73's
            let rrr_payload: BitVec<u8, Msb0> = generate_random_bitvec(300);
            rrr_message.set_payload(rrr_payload.clone()).unwrap();

            // Get the 64-bit CSPRNG state, which we do not reveal. The point is that receivers
            // can calculate it later, once we've revealed an *earlier* state in the sequence at
            // a *later* time.
            let csprng_state_bits = u64_to_bitvec(csprng.get_rand(&current_time).unwrap());
            //println!("CSPRNG state bits for timestamp {} are {}", current_time.clone(), bitvec_to_u64(&csprng_state_bits.clone()));

            // Get the timestamp encoded as 72 bits from the current time
            let timestamp_bits = bytes_to_bitvec(&timestamp_as_bytes(&current_time), 72);

            let hash_20bits = hash_rrr_payload(rrr_message.payload.clone(), &csprng_state_bits, &timestamp_bits);

            rrr_message.set_hmac(hash_20bits).unwrap();

            println!("{}", rrr_message);

            // Transmit the message
            messages_transmitted.push(RadioMessage::RRR(rrr_message));
        }
    }

    // Now begin simulation at *receiver* side, assuming a fixed probability of message loss
    println!();
    println!("Starting receiver simulation with message loss probability p = {}", p_loss);
    println!();

    // Initialize the receiver's "state" -- have they successfully decoded a CSPRNG state? If so,
    // when was the last timestamp? They need a CSPRNG state to validate previous messages

    let mut pending_messages_to_validate: Vec<RRRMessage> = Vec::new();
    let mut num_messages_lost = 0;
    for (_, message) in messages_transmitted.iter().enumerate() {
        let is_lost = rng.gen::<f32>() <= p_loss;
        if is_lost {
            // If the receiver lost the message, skip processing it
            num_messages_lost += 1;
            continue
        }

        match message {
            RadioMessage::CQ(cq_message) => {
                // A CQ message reveals a CSPRNG state, which we can use to validate previously received messages
                // we get timestamp from the transmitted message here, but in the real world, we'd have it because clocks are synchronized
                let timestamp_bits = bytes_to_bitvec(&timestamp_as_bytes(&cq_message.clone().timestamp), 72);

                // The callsign is part of the CQ; here we hardcode it instead of getting it from
                // the 77-bit payload like we'd do in the real protocol
                let padded_callsign_bytes = SuperfoxCsprng::generate_padded_callsign_bytes("N5J".to_string());

                // Get the bits of just the message
                let mut concatenated_message_bits: BitVec<u8, Msb0> = cq_message.callsign_and_location.clone();
                concatenated_message_bits.extend_from_bitslice(&cq_message.csprng_state);
                concatenated_message_bits.extend_from_bitslice(&timestamp_bits);

                let signature_bits = cq_message.clone().signature;

                // Use the public key (communicated out-of-band, if we want to keep the CQ message
                // smaller) to validate the CSPRNG state
                let public_key_bits = bytes_to_bitvec(&pk_bytes, 512);

                let is_cq_message_signature_valid = validate_bls_signature(&concatenated_message_bits, &signature_bits, &public_key_bits);
                if is_cq_message_signature_valid {
                    println!("Found valid CQ message signature for CQ message at {}", cq_message.timestamp.clone());
                }
                else {
                    println!("Found INVALID CQ message signature for CQ message at {}", cq_message.timestamp.clone());
                }

                for pending_message in &pending_messages_to_validate {
                    let message_is_valid = validate_rrr_message(cq_message, pending_message, &padded_callsign_bytes);

                    // Find the time difference between when the RRR message was originally received
                    // and when we successfully received the CQ message we used to validate it.
                    // This is effectively a measure of the time between when a Hound receives an
                    // RRR message & when they figure out whether the message is authentic.
                    let time_to_validate = cq_message.timestamp - pending_message.timestamp;
                    if message_is_valid {
                        println!("{} -- **VALID SIGNATURE** (time-to-validate: {})", pending_message.clone(), format_duration(time_to_validate));
                    }
                    else {
                        println!("{} -- **INVALID SIGNATURE** (time-to-validate: {})", pending_message.clone(), format_duration(time_to_validate))
                    }
                }
                // All pending messages processed, so clear the queue
                pending_messages_to_validate.clear();
            },
            RadioMessage::RRR(rrr) => {
                // Add the RRR message to the buffer (we'd print it on the screen in WSJT-X, but perhaps later, change it's color
                // when we later validate it)
                pending_messages_to_validate.push(rrr.clone());
                // println!("RRR message at {}", rrr.timestamp)
            },
        }
    }
    // Handle messages we've received but not yet validated, since we stopped receiving before we
    // could get a CQ with updated csprng_state.
    for pending_message in &pending_messages_to_validate {
        println!("{} -- **SIMULATION ENDED BEFORE RECEIVING CQ**", pending_message.clone());
    }
    pending_messages_to_validate.clear();
    println!();
    println!("Receiver lost {} messages out of {}.", num_messages_lost, &messages_transmitted.len());
    println!();

    // Print some approximate statistical calculations for how long it will take for a receiver to
    // validate a message, given the loss probability
    let p_success = 1.0 - p_loss;
    let minutes_between_cq = 5;
    let rrr_messages_per_interval = (minutes_between_cq - 1) * 2 + 1;
    let frac_rrr_messages_per_interval = rrr_messages_per_interval as f64/(rrr_messages_per_interval as f64 + 1_f64);
    println!();
    println!();
    println!();
    println!("CQ Message Reception Analysis");
    println!("-----------------------------");
    println!("Probability of message loss: {:.2}%", p_loss * 100.0);
    println!("Time between CQ messages: {} minutes", minutes_between_cq);
    println!("Efficiency (fraction of total messages that are RRR): {:.2}% ", frac_rrr_messages_per_interval * 100_f64);
    println!("QSO Throughput Loss (relative to existing SuperFox protocol): {:.2}%",  (1_f64 - frac_rrr_messages_per_interval) * 100_f64);
    println!();

    println!("Cumulative percentage of hounds that have received at least one CQ message:");
    println!("-----------------------------------------------------------------------------");
    for k in 1..=10 {
        let cumulative_prob = 1.0 - f64::powi(p_loss as f64, k);
        println!("After {} CQ messages: {:.2}%", k, cumulative_prob * 100.0);
    }
    println!();

    println!("Cumulative temporal distribution:");
    println!("------------------------------------------");

    // Assume the RRR message the hound receives is uniformly distributed in the interval between
    // CQs, and calculate the expectation time to the 1st CQ
    let mut expected_time_between_rrr_and_cq_uniform = 0_f64;
    for i in 0..rrr_messages_per_interval {
        let time_offset_minutes =  (i as f64 + 1_f64) * 30_f64/60_f64;
        expected_time_between_rrr_and_cq_uniform += (1_f64/rrr_messages_per_interval as f64) * time_offset_minutes
    }

    for minute in (5..=60).step_by(5) {
        let k = minute / minutes_between_cq;
        let cumulative_prob = 1.0 - f64::powi(p_loss as f64, k);
        // adjusted_minute accounts for a uniform probability of where in the interval between
        // CQ messages a hound receives an RRR message from the fox, i.e. an average of ~2.5 minutes
        // for a 5-minute interval between CQ's.
        let adjusted_minute = minute as f64 - 5_f64 + expected_time_between_rrr_and_cq_uniform;
        println!("By {} minutes: {:.2}%", adjusted_minute, cumulative_prob * 100.0);
    }
    println!();

    let expected_time = minutes_between_cq as f64 / p_success as f64 - 5_f64 + expected_time_between_rrr_and_cq_uniform;
    println!("Expected time (geometric distribution) to receive first CQ message: {:.2} minutes", expected_time);

    let confidence_interval_95 = minutes_between_cq as f64 * f64::ceil(f64::log(0.05, 10.0) / f64::log(p_loss as f64, 10.0)) - 5_f64 + expected_time_between_rrr_and_cq_uniform;
    println!("Expected delay after which at least 95% of hounds will receive a CQ message: {:.2} minutes", confidence_interval_95);

}

fn hash_rrr_payload(rrr_payload: BitVec<u8, Msb0>, csprng_state_bits: &BitVec<u8, Msb0>, timestamp_bits: &BitVec<u8, Msb0>) -> BitVec<u8, Msb0> {
    // Concatenate the RRR payload, csprng state, and timestamp, hash & then truncate to 20 bits
    let mut concatenated_message_bits: BitVec<u8, Msb0> = rrr_payload.clone();
    concatenated_message_bits.extend_from_bitslice(&csprng_state_bits);
    concatenated_message_bits.extend_from_bitslice(&timestamp_bits);

    let hash = blake3::hash(&pad_bitvec_to_bytes(&concatenated_message_bits));
    let hash_20bits = bytes_to_bitvec(hash.as_bytes(), 20);
    hash_20bits
}

// Function to simulate packing regular messages into an 80 bit output.
// The real FT8 creates a 77-bit message - this is just to approximate. Use it for
// CQ + callsign, or the individual signal report + RR73 messages.
fn pack80(message_bytes: &[u8; 13]) -> [u8; 10] {
    let hash = blake3::hash(message_bytes);

    let mut result = [0u8; 10];
    result.copy_from_slice(&hash.as_bytes()[0..10]);
    result
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
/// # Examples
///
/// ```
/// use bitvec::prelude::*;
///
/// let bv = bitvec![u8, Msb0; 1, 0, 1, 1, 0];
/// assert_eq!(format_bitvec(&bv), "10110");
/// ```
pub fn format_bitvec<T: BitStore>(bits: &BitVec<T, Msb0>) -> String {
    bits.iter().map(|b| if *b { '1' } else { '0' }).collect()
}

/// Converts a byte slice to a BitVec with a specific number of bits.
///
/// This function takes a slice of bytes and converts it to a BitVec,
/// truncating or zero-padding as necessary to achieve the specified number of bits.
///
/// # Arguments
///
/// * `bytes` - A slice of bytes to convert.
/// * `num_bits` - The desired number of bits in the resulting BitVec.
///
/// # Returns
///
/// A BitVec containing the specified number of bits from the input byte slice.
///
/// # Examples
///
/// ```
/// use bitvec::prelude::*;
///
/// let bytes = [0b10110011, 0b01011010];
/// let bv = bytes_to_bitvec(&bytes, 12);
/// assert_eq!(bv.len(), 12);
/// assert_eq!(format_bitvec(&bv), "101100110101");
/// ```
pub fn bytes_to_bitvec(bytes: &[u8], num_bits: usize) -> BitVec<u8, Msb0> {
    let mut bv = BitVec::<u8, Msb0>::from_slice(bytes);
    bv.truncate(num_bits);
    if bv.len() < num_bits {
        bv.resize(num_bits, false);
    }
    bv
}

/// Pads a message string and converts it to a fixed-size UTF-8 byte array.
///
/// This function takes a message string, pads it with spaces if it's too short,
/// truncates it if it's too long, and converts it to a UTF-8 byte array of exactly 13 bytes.
///
/// # Arguments
///
/// * `message` - The input message string.
///
/// # Returns
///
/// A 13-byte array containing the padded and UTF-8 encoded message.
///
/// # Examples
///
/// ```
/// let callsign = "W1AW";
/// let message = format!("CQ {}", callsign);
/// let padded = pad_and_encode_message(&message);
/// assert_eq!(padded.len(), 13);
/// assert_eq!(std::str::from_utf8(&padded).unwrap().trim(), "CQ W1AW");
/// ```
fn pad_and_encode_message(message: &str) -> [u8; 13] {
    let mut padded = [b' '; 13]; // Initialize with 13 space bytes
    let utf8_bytes = message.as_bytes();

    // Copy the bytes, up to 13 or the length of utf8_bytes, whichever is smaller
    let copy_len = utf8_bytes.len().min(13);
    padded[..copy_len].copy_from_slice(&utf8_bytes[..copy_len]);

    padded
}


/// Generates a BLS signature from a BitVec message using the G1 curve.
///
/// This function pads the input BitVec to a full byte slice, hashes it to a point on G1,
/// and then generates a BLS signature using the provided private key.
///
/// # Arguments
///
/// * `message` - The input message as a BitVec.
/// * `private_key` - The private key as a ScalarField element.
///
/// # Returns
///
/// The BLS signature as a G1Affine point.
///
/// # Examples
///
/// ```
/// use bitvec::prelude::*;
/// use ark_bls12_381::Fr as ScalarField;
///
/// let message = bitvec![u8, Msb0; 1, 0, 1, 1, 0, 0, 1];
/// let private_key = ScalarField::rand(&mut rng);
/// let signature = generate_bls_signature(&message, &private_key);
/// ```
pub fn generate_bls_signature(message: &BitVec<u8, Msb0>, private_key: &ScalarField) -> G1Affine {
    // Pad the BitVec to a full byte slice
    let padded_message = pad_bitvec_to_bytes(message);

    // Hash the padded message to G1
    let hashed_message = hash_message_to_g1(&padded_message);

    // Generate the signature
    hashed_message.mul(private_key).into_affine()
}

pub fn validate_bls_signature(data: &BitVec<u8, Msb0>, signature_bits: &BitVec<u8, Msb0>, public_key_bits: &BitVec<u8, Msb0>) -> bool {
    // Convert signature bits to bytes
    let signature_bytes = pad_bitvec_to_bytes(signature_bits);
    // Deserialize signature bytes -> point on G1
    let signature = G1Affine::deserialize_compressed(&signature_bytes[..]).unwrap();

    // Convert public key bits to bytes
    let public_key_bytes = pad_bitvec_to_bytes(public_key_bits);
    // Deserialize public key bytes -> point on G2
    let public_key = G2Affine::deserialize_compressed(&public_key_bytes[..]).unwrap();

    // Compute the hashed message as a point on G1
    let hashed_message = hash_message_to_g1(&pad_bitvec_to_bytes(data));

    // Verify the signature
    let lhs = Bn254::pairing(signature, G2Affine::generator());
    let rhs = Bn254::pairing(hashed_message, public_key);

    lhs == rhs
}

/// Converts a DateTime<Utc> into a 9-byte array representation.
///
/// The resulting array contains:
/// - Bytes 0-3: Year (big-endian)
/// - Byte 4: Month
/// - Byte 5: Day
/// - Byte 6: Hour
/// - Byte 7: Minute
/// - Byte 8: Second
///
/// # Arguments
///
/// * `valid_time` - A DateTime<Utc> to be converted.
///
/// # Returns
///
/// A 9-byte array containing the timestamp representation.
///
fn timestamp_as_bytes(valid_time: &DateTime<Utc>) -> [u8; 9] {
    let mut output = [0u8; 9];

    output[0..4].copy_from_slice(&valid_time.year().to_be_bytes());
    output[4] = valid_time.month() as u8;
    output[5] = valid_time.day() as u8;
    output[6] = valid_time.hour() as u8;
    output[7] = valid_time.minute() as u8;
    output[8] = valid_time.second() as u8;

    output
}

/// Generates a BitVec of the specified length with random bits.
///
/// # Arguments
///
/// * `length` - The number of random bits to generate.
///
/// # Returns
///
/// A BitVec<u8, Msb0> of the specified length with random bits.
///
/// # Examples
///
/// ```
/// let random_bits = generate_random_bitvec(300);
/// assert_eq!(random_bits.len(), 300);
/// ```
fn generate_random_bitvec(length: usize) -> BitVec<u8, Msb0> {
    let mut rng = rand::thread_rng();
    let mut bv = BitVec::with_capacity(length);

    for _ in 0..length {
        bv.push(rng.gen::<bool>());
    }

    bv
}

fn validate_rrr_message(cq_message: &CQMessage, rrr_message: &RRRMessage, padded_callsign_bytes: &[u8; CALLSIGN_MAX_BYTES]) -> bool {
    let cq_time = cq_message.timestamp;
    let rrr_time = rrr_message.timestamp;

    // Ensure the RRR message is before the CQ message
    if rrr_time >= cq_time {
        return false;
    }

    // Calculate the number of 15-second intervals between RRR and CQ
    let time_diff = cq_time - rrr_time;
    let intervals = time_diff.num_seconds() / 15;

    // Start with the CSPRNG state from the CQ message
    let cq_csprng_state = bitvec_to_u64(&cq_message.csprng_state);

    // Advance the CSPRNG state backwards to the time of the RRR message
    let rrr_csprng_state = match SuperfoxCsprng::advance_multiple_steps(cq_csprng_state, intervals as u64, padded_callsign_bytes, &cq_time) {
        Ok(state) => state,
        Err(_) => return false, // If there's an error, consider the message invalid
    };

    let csprng_state_bits = u64_to_bitvec(rrr_csprng_state);
    let timestamp_bits = bytes_to_bitvec(&timestamp_as_bytes(&rrr_message.timestamp), 72);

    let computed_hash = hash_rrr_payload(rrr_message.payload.clone(), &csprng_state_bits, &timestamp_bits);

    computed_hash == rrr_message.hmac
}


/// Pads a BitVec to a full byte slice.
fn pad_bitvec_to_bytes(bits: &BitVec<u8, Msb0>) -> Vec<u8> {
    let mut padded = bits.clone();
    while padded.len() % 8 != 0 {
        padded.push(false);
    }
    padded.as_raw_slice().to_vec()
}

/// Hashes a message to a point on the G1 curve.
fn hash_message_to_g1(message: &[u8]) -> G1Affine {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let scalar = ScalarField::from_le_bytes_mod_order(&result);
    G1Affine::generator().mul(scalar).into_affine()
}

/// Hashes a message to a point on the G2 curve.
#[allow(dead_code)]
fn hash_message_to_g2(message: &[u8]) -> G2Affine {
    // Note: This is a simplified hash-to-curve operation and should not be used in production
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let scalar = ScalarField::from_le_bytes_mod_order(&result);
    G2Affine::generator().mul(scalar).into_affine()
}

fn u64_to_bitvec(value: u64) -> BitVec<u8, Msb0> {
    let mut bv = BitVec::<u8, Msb0>::with_capacity(64);
    bv.extend_from_raw_slice(&value.to_be_bytes());
    bv
}

fn bitvec_to_u64(bv: &BitVec<u8, Msb0>) -> u64 {
    // Convert BitVec to a byte array
    let bytes: [u8; 8] = bv.as_raw_slice().try_into().unwrap();

    // Convert the byte array to u64
    u64::from_be_bytes(bytes)
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.num_seconds();
    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;

    if minutes > 0 {
        format!("{}m{}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

// use ark_bls12_381::{Fr as ScalarField, G1Affine, G1Projective, Bls12_381};
// use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
// use ark_ff::{BigInteger, Field, PrimeField};
// use ark_std::UniformRand;
// use sha2::{Digest, Sha256};
//
// fn main() {
//     let mut rng = ark_std::rand::thread_rng();
//
//     // Generate private key
//     let private_key: ScalarField = ScalarField::rand(&mut rng);
//
//     // Compute public key
//     let public_key = G1Affine::generator().mul_bigint(private_key).into_affine();
//
//     // Message to sign
//     let message = b"Hello, world!";
//
//     // Hash the message (in a real implementation, you'd use a hash-to-curve function)
//     let hashed_message = hash_message(message);
//
//     // Sign the message
//     let signature = G1Affine::generator().mul_bigint(private_key * hashed_message).into_affine();
//
//     println!("Private key: 0x{}", hex::encode(private_key.into_bigint().to_bytes_le()));
//     println!("Public key: 0x{}", hex::encode(public_key.to_compressed()));
//     println!("Message: {:?}", std::str::from_utf8(message).unwrap());
//     println!("Signature: 0x{}", hex::encode(signature.to_compressed()));
//
//     // Verify the signature
//     let g2_gen = ark_bls12_381::G2Affine::generator();
//     let lhs = Bls12_381::pairing(signature, g2_gen);
//     let rhs = Bls12_381::pairing(public_key, g2_gen.mul(hashed_message).into_affine());
//
//     println!("Signature valid: {}", lhs == rhs);
// }
//
// fn hash_message(message: &[u8]) -> ScalarField {
//     let mut hasher = Sha256::new();
//     hasher.update(message);
//     let result = hasher.finalize();
//     ScalarField::from_le_bytes_mod_order(&result)
// }