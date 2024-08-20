
use std::collections::{BTreeMap, Bound};
use std::time::Instant;
use chrono::{DateTime, Utc, Duration, Timelike, Datelike};

use crate::messages::{CALLSIGN_MAX_BYTES, CALLSIGN_ALLOWED_CHARS};

// Must be at least 8 + 13 + 9 bytes for the state + callsign + timestamp, respectively
const INTERNAL_HASH_INPUT_SIZE_BYTES: usize = 32;

const MAX_CACHE_SIZE: usize = 2 * 1024 * 1024 * 8 / 64;

#[allow(dead_code)]
pub struct SuperfoxCsprng {
    pub seed: u64,
    pub csprng_epoch: DateTime<Utc>,
    pub callsign: [u8; CALLSIGN_MAX_BYTES],
    pub cache: BTreeMap<DateTime<Utc>, u64>
}


impl SuperfoxCsprng {
    pub fn new(seed: u64, callsign: &str, csprng_epoch: &DateTime<Utc>) -> Result<Self, String> {
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

    pub fn generate_padded_callsign_bytes(callsign: String) -> [u8; 13] {
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