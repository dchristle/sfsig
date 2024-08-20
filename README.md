## Prerequisites
Install Rust & Cargo locally via: 
```
curl https://sh.rustup.rs -sSf | sh
```
(see: https://doc.rust-lang.org/cargo/getting-started/installation.html)

## Compile & Run

`sfsig` is a command line executable. After cd'ing into the repo directory, run:

```
cargo run --release
```

To pass options, separate by a double hyphen as:
```
cargo run --release -- -p 0.5 -c N5J -n 100
```

### Usage

```
Usage: sfsig [OPTIONS]

Options:
  -p, --p-loss <P_LOSS>
          Probability of a Hound failing to decode a message sent by the Fox

          [default: 0.2]

  -c, --callsign <CALLSIGN>
          Callsign of the Fox station

          [default: N5J]

  -n, --num-periods-to-simulate <NUM_PERIODS_TO_SIMULATE>
          Number of 15 second time periods to simulate

          [default: 90]

  -n, --num-final-cq-messages <NUM_FINAL_CQ_MESSAGES>
          Number of CQ messages a Fox should send at the end of a session

          In the presence of message loss, sending multiple "CQ"'s at the end increases the chance for all hounds -- especially the last ones before the station signs off -- to get the data needed to validate.

          [default: 3]

  -m, --minutes-between-cq <MINUTES_BETWEEN_CQ>
          Minutes between each "CQ" message.

          The longer this parameter, the longer the average wait between a hound receiving an RRR & being able to validate it.

          [default: 5]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

### Example Output

```
Simulation parameters:
P(loss): 0.2
Callsign: N5J
Number of periods to simulate: 20 (4.75% minutes)
Number of final CQ messages: 3

Private key: 0x6d60eb870e80f4c4407f962792a01f96166fe0122490a34bbef9dad2534d7a01
Private key size: 256 bits
Public key (G2): 0xded4dc19cd6fd4f1180dd11d8aa382f79bda6583a58dba0229b1ace8f034cc107ff75dd20d2d47b51a63cd8793b12daa2fc720c19f9185c01e8eb35bb1c60e8a
Public key size: 512 bits
Message (arbitrary size): "Hello, world!"
Signature (G1): 0x6151ddeef03e654291c7050f551fcb7347166870a580e5441d249ff45c3a0aad
Signature size: 256 bits
Signature valid: true
k is 4 and cache_interval is 16, implying 179886 cached values
Validated epoch is 2026-01-01 00:00:00 UTC, start time is 2024-08-19 07:34:45 UTC
Populating cache...
Finished computing 2878181 hash values and caching 2878181 entries in 0.31576684 seconds.

Starting simulation of 20 periods, starting from coalesced UTC time 2024-08-19 07:35:00 UTC.

2024-08-19 07:35:00: <... 77 callsign_and_location bits ...> + 1110010101000110011001001110011001010000101000011110001000000001 CSPRNG state (64 bits) + 0010000110000111001101001111110011011111101101010111011001001000001101100001110110110110110110000001011000101111000010111100100010001010100011110011001001000011100011010000001001101000101001100100011111000000100011100111101110010011110000000100001000100011 BLS signature (256 bits) -- (397 bits total, before FEC)
2024-08-19 07:36:00: <... 300 signal report/RR73 bits ...> + 01011011110000110100 hash (20 bits) -- (320 bits total, before FEC)
2024-08-19 07:36:30: <... 300 signal report/RR73 bits ...> + 01111111101010011011 hash (20 bits) -- (320 bits total, before FEC)
2024-08-19 07:37:00: <... 300 signal report/RR73 bits ...> + 10000011001011011110 hash (20 bits) -- (320 bits total, before FEC)
2024-08-19 07:37:30: <... 300 signal report/RR73 bits ...> + 01000001001110101011 hash (20 bits) -- (320 bits total, before FEC)
2024-08-19 07:38:00: <... 300 signal report/RR73 bits ...> + 00111111010111111101 hash (20 bits) -- (320 bits total, before FEC)
2024-08-19 07:38:30: <... 300 signal report/RR73 bits ...> + 01100011110110101010 hash (20 bits) -- (320 bits total, before FEC)
2024-08-19 07:39:00: <... 300 signal report/RR73 bits ...> + 10010010101000110100 hash (20 bits) -- (320 bits total, before FEC)
2024-08-19 07:39:15: <... 77 callsign_and_location bits ...> + 0001110010111010100111011011101100110001010010001001110011000010 CSPRNG state (64 bits) + 0010111101011001010001001001101011000100100111001100000010010101100101001000001011111010111100000010001110010101100101010001010101111101111011111010101011101011100111111001101100001100011111010111101011111000010111001110111010111101101001010110101100001000 BLS signature (256 bits) -- (397 bits total, before FEC)
2024-08-19 07:39:30: <... 77 callsign_and_location bits ...> + 0001001111011010001011100011001101110010011001011110001111010001 CSPRNG state (64 bits) + 0010110011011101011100011111100011111101011001101001110010000010000110010111111011111111011010100011000100000111010011110001011011011010010001100001010100100101110110000001011110001011000110011110100010000000110111101011101101100010110000000000100100001001 BLS signature (256 bits) -- (397 bits total, before FEC)
2024-08-19 07:39:45: <... 77 callsign_and_location bits ...> + 1000011000011101001000100100101010010111100101100011100000010111 CSPRNG state (64 bits) + 0000101101100101010111001110011010011010001110100101101101101101110000110001000011111000011011101011111010011011001000010100001110010001110101001101010001110110111110110101000011111000101111001110010001101101110011010001001011001110101110010011101010001100 BLS signature (256 bits) -- (397 bits total, before FEC)

Starting receiver simulation with message loss probability p = 0.2

Found valid CQ message signature for CQ message at 2024-08-19 07:35:00 UTC
Found valid CQ message signature for CQ message at 2024-08-19 07:39:30 UTC
2024-08-19 07:36:30: <... 300 signal report/RR73 bits ...> + 01111111101010011011 hash (20 bits) -- (320 bits total, before FEC) -- **VALID SIGNATURE** (time-to-validate: 3m0s)
2024-08-19 07:37:30: <... 300 signal report/RR73 bits ...> + 01000001001110101011 hash (20 bits) -- (320 bits total, before FEC) -- **VALID SIGNATURE** (time-to-validate: 2m0s)
2024-08-19 07:38:00: <... 300 signal report/RR73 bits ...> + 00111111010111111101 hash (20 bits) -- (320 bits total, before FEC) -- **VALID SIGNATURE** (time-to-validate: 1m30s)
2024-08-19 07:39:00: <... 300 signal report/RR73 bits ...> + 10010010101000110100 hash (20 bits) -- (320 bits total, before FEC) -- **VALID SIGNATURE** (time-to-validate: 30s)

Receiver lost 5 messages out of 11.




CQ Message Reception Analysis
-----------------------------
Probability of message loss: 20.00%
Time between CQ messages: 5 minutes
Efficiency (fraction of total messages that are RRR): 90.00%
QSO Throughput Loss (relative to existing SuperFox protocol): 10.00%

Cumulative percentage of hounds that have received at least one CQ message:
-----------------------------------------------------------------------------
After 1 CQ messages: 80.00%
After 2 CQ messages: 96.00%
After 3 CQ messages: 99.20%
After 4 CQ messages: 99.84%
After 5 CQ messages: 99.97%
After 6 CQ messages: 99.99%
After 7 CQ messages: 100.00%
After 8 CQ messages: 100.00%
After 9 CQ messages: 100.00%
After 10 CQ messages: 100.00%

Cumulative temporal distribution:
------------------------------------------
By 2.5 minutes: 80.00%
By 7.5 minutes: 96.00%
By 12.5 minutes: 99.20%
By 17.5 minutes: 99.84%
By 22.5 minutes: 99.97%
By 27.5 minutes: 99.99%
By 32.5 minutes: 100.00%
By 37.5 minutes: 100.00%
By 42.5 minutes: 100.00%
By 47.5 minutes: 100.00%
By 52.5 minutes: 100.00%
By 57.5 minutes: 100.00%

Expected time (geometric distribution) to receive first CQ message: 3.75 minutes
Expected delay after which at least 95% of hounds will receive a CQ message: 7.50 minutes
```
