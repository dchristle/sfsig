# SuperFox "BTO" Protocol RFC

Last updated: 2024-09-02

## 1. Context and Scope

The BTO Protocol is designed to augment the "SuperFox" mode of the FT8 amateur radio protocol with the ability to authenticate legitimate transmitting stations. 

So-called "pirate" stations are motivated to impersonate authentic "DXpedition" stations. There is no intrinsic mechanism within amateur radio to prevent one station from using any callsign, so impersonation is trivial. Besides impersonation, pirates may also be motivated to interfere with a legitimate DXpedition station.

This protocol aims to provide a secure and efficient method for authenticating messages in DXpedition scenarios, where high-volume, low-bandwidth communications are critical.


## 2. Goals and Non-Goals

### 2.1 Goals

- Provide a secure method for authenticating SuperFox mode messages
- Provide a secure method for Receivers (Hounds) to authenticate their QSO exchange (contact) with a transmitting station (Fox) is authentic
- Minimize bandwidth overhead for authentication, fitting within the limited amount of spare bits in the existing SuperFox protocol
- Prevent replay attacks and message forgery
- Support high-volume QSO throughput
- Enable offline verification of messages

### 2.2 Non-Goals

- Provide encryption for message contents
- Require continuous internet connectivity for operation
- Replace existing FT8/SuperFox protocols entirely

## 3. Design


The BTO Protocol is designed to work within the constraints of the existing SuperFox mode while providing robust authentication. It leverages BLS (Boneh-Lynn-Shacham) digital signatures combined with a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to achieve its goals. 

It achieves the following:

- The "authentication signature" messages use strong cryptographic primitives, achieving roughly ~90 bits of security. These message types indicate to Hound stations that the Fox station is legitimate, and also reveal the data necessary to authenticate all previously sent standard type messages.
- Message loss is tolerated. Authentication signature messages can be lost and never retransmitted. As long as an authentication signature payload (the 56-bit RNG state + signature) of a later timestamp is received, all earlier messages can be authenticated.
- Pirates cannot forge messages without either:
  1) Solving the discrete logarithm problem for a ~90-bit security level elliptic curve
  2) Brute forcing the 56-bit random number generator state space (roughly ~2^56 combinations)
  3) Randomly generating a 20-bit signature QSO (only 1 in ~1 million random chance per 15-second transmission period attempt)
- Pirates cannot replay old transmissions or RNG states, since the time of message reception is compared against what is effectively a signed timestamp from the Fox
- The algorithm implementation can be entirely public while remaining secure, which is compatible with the WSJTX license
- No reliance on sharing private keys between a DXpedition and WSJTX/NCDXF. Using asymmetric cryptography means we avoid headaches of password sharing, transmitting secret data over insecure channels, or other compromise.
- New keys are easy to generate, so each DXpedition can have their own key. There is no reliance on a fixed set of pre-generated keys hardbaked into the protocol code.
- DXpedition keys can be expired & even revoked. These are good security practices.
- QSO throughput remains high. A 5-minute period between authentication signature messages implies a 90% throughput efficiency.
- Since a revealed CSPRNG state allows verifying all previously sent messages, a published RNG state at the end of a DXpedition (i.e. via the Internet) would allow signature verification of all messages from the entire DXpedition.
- It's possible (but not required) for Fox transmitters to synchronize their CSPRNG outputs, which would allow an authentication signature message received from one transmitter to verify signal report/acknowledgement messages from another.

The core idea of using signed RNG states to validate past messages also appeara in the literature as the [TESLA Broadcast Authentictation Protocol](https://people.eecs.berkeley.edu/~tygar/papers/TESLA_broadcast_authentication_protocol.pdf).

### 3.1 SuperFox Constraints

The SuperFox protocol uses the IV3NWV Q-ary Polar Code with parameters (n,k) = (127,50). Each SuperFox transmission carries a payload of 329 bits. The SuperFox protocol defines several message types, each with its own bit allocation.

### 3.2 Key Components

1. BLS Digital Signatures
2. Cryptographically Secure Pseudorandom Number Generator (CSPRNG)
3. Special CQ Messages
4. RRR Messages (containing signal reports & RR73's)

### 3.3 BTO Protocol Overview

1. Key Generation and Distribution:
    - The Fox (transmitting station) generates a BLS key pair.
    - Though not strictly required, the Fox's public key can be transmitted to the WSJT-X developers/NCDXF, and signed using their private keys. 
    - The Fox's public key, including any signature(s) from the WSJTX/NCDXF keys, is distributed to Hounds (receiving stations) out-of-band. Suggestions for how to do this are described later in this document.

2. CSPRNG Initialization:
    - The Fox initializes a CSPRNG with a secret seed.
    - A sequence of RNG values is pre-computed, starting from a future date (e.g., 2026-01-01 00:00:00) and ending at the current time.
    - Each step in the RNG sequence corresponds to a 15-second time interval (FT8 transmission period).

3. Special Authentication Signature Message Transmission:
    - Transmitted at regular intervals (e.g., every 5 minutes)
    - Contains:
        - Fox callsign (28 bits for standard callsign or 58 bits for compound callsign)
        - Grid locator (15 bits)
        - CSPRNG state (56 bits)
        - BLS signature (~185 bits)

4. RRR Message Transmission:
    - Transmitted between authentication signature & other messages
    - Contains:
        - Signal report/RR73 payload (existing SuperFox format)
        - 20-bit hash derived from the current CSPRNG state

5. Message Reception and Validation:
    - Hounds receive and store messages
    - Messages are validated when the next CQ message is received
    - The revealed CSPRNG state allows verification of previous messages

![image](https://github.com/user-attachments/assets/966b9a6f-4177-4b27-b8b5-4799bbc26ef1)



### 3.4 CSPRNG Design and Security Considerations

The Cryptographically Secure Pseudorandom Number Generator (CSPRNG) is a cornerstone of the BTO Protocol's security model. Its implementation leverages an inverse relationship between CSPRNG state progression and time to achieve forward security. This section details the design and implementation of the CSPRNG.

#### 3.4.1 CSPRNG Algorithm Overview

The CSPRNG used in the BTO Protocol is based on the principle of using a cryptographic hash function to generate pseudorandom numbers. This approach is similar to the [Hash_DRBG](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-90ar1.pdf) (Hash-Based Deterministic Random Bit Generator) specified by NIST, but with modifications to suit the specific requirements of the BTO Protocol.

Key features of the CSPRNG:

1. Configurable State Size: The CSPRNG allows for a flexible state size, chosen to be 56 bits to fit within the constraints of the SuperFox message format.

2. Use of BLAKE3 Hash Function: The algorithm uses BLAKE3 as its underlying cryptographic hash function. BLAKE3 is chosen for its security properties, performance, availability in [C](https://github.com/BLAKE3-team/BLAKE3), [Python](https://pypi.org/project/blake3/), and [Rust](https://docs.rs/blake3/latest/blake3/), indifferentiability from a random oracle, and resistance to length extension attacks.

3. Additional Input: To mitigate potential issues with RNG orbits (cycles in the output sequence) and precomputation attacks, the algorithm incorporates additional inputs beyond the state:
    - Current timestamp (rounded to 15-second intervals, as usual)
    - DXpedition callsign

4. State Update Mechanism: The next state is derived by hashing the current state along with the additional inputs, then truncating BLAKE3's 256-bit hash output to the desired state size. Including the timestamp in the hash input is analogous to HASH_DRBG's use of a counter.


#### 3.4.2 CSPRNG Algorithm Details

The CSPRNG algorithm operates as follows:

1. Input Preparation:
    - Current 56-bit state (S)
    - Callsign (C): 28-bits or 56-bits, zero-padded if necessary
    - Timestamp (T): Current UTC time rounded to the nearest 15-second interval

2. Hash Input Construction:
    - Concatenate `S || C || T` into a 32-byte (256-bit) input buffer
    - `S` occupies bits 0-55 (56 bits)
    - `C` occupies bytes 56-113 (58 bits)
    - `T` occupies bits 114-149 (36 bits), formatted as:
        - Year (14 bits)
        - Month (4 bits)
        - Day (5 bits)
        - Hour (5 bits)
        - Minute (6 bits)
        - Second (2 bits, since only 15-second increments from the UTC minute are allowed)
    - Remaining bits are left as zeros

3. Hash Computation:
    - Compute `H = BLAKE3(input buffer)`

4. State Update:
    - New state `S' = H[0:7] ⊕ H[7:14]`, meaning that the first 7 bytes (56-bits) are XOR'd with the second 7 bytes, and the resulting 7 byte output is the new state. An even simpler alternative would be returning `H[0:7]` directly.

5. Output:
    - The new state `S'` is both the CSPRNG output and the input state for the next iteration

### 3.4 CSPRNG and Security Considerations

The Cryptographically Secure Pseudorandom Number Generator (CSPRNG) is a cornerstone of the BTO Protocol's security model. Its implementation leverages an inverse relationship between CSPRNG state progression and time to achieve forward security, while allowing any receiver to verify messages from earlier timestamps.

1. Algorithmic Primitives, State Size and Initialization:
   - Repeated hashing with BLAKE3 generates outputs indistinguishable from random & can't be easily reversed
   - CSPRNG state: 56 bits (constrained by message size limits)
   - State space: ~2^56 possible states (sufficient for typical DXpedition durations)
   - Initialization:
      - Fox station randomly selects a 56-bit seed
      - Fox chooses a reference UTC datetime in the future well beyond the DXpedition (e.g., a DXpedition in 2024 could choose 2027-01-01 00:00:00)

2. Temporal-CSPRNG Mapping:
   - The initial CSPRNG state corresponds to the chosen future reference datetime
   - Each CSPRNG iteration maps to a 15-second step backward in time
   - Time granularity: UTC times rounded to :00, :15, :30, or :45 seconds past the minute
   - Formal mapping:
     `T(s) = ReferenceDateTime - (15 seconds * s)`
     where `s` is the number of CSPRNG iterations from the initial state

3. Forward Computation, Backward Time Progression:
   - CSPRNG design: Easy to compute forward in sequence, difficult to reverse
   - Time progression: Each forward CSPRNG computation corresponds to a backward step in time
   - Security implication:
     a. Given a CSPRNG state, one can easily compute states for all previous times
     b. Computing states for future times requires brute-forcing the CSPRNG, which is computationally infeasible

4. Authentication Mechanism:
   - Fox transmits: Current CSPRNG state + corresponding UTC timestamp
   - Hound verification process:
     a. Compute forward from received state to reach states for all previous timestamps
     b. Use these states to verify the authenticity of previously received messages
   - Pirate prevention: Cannot feasibly compute CSPRNG states for future timestamps

5. Brute Force Resistance:
   - Attack complexity: 2^56 operations to forge a future state
   - Time-bounded security: Infeasible within typical DXpedition timeframes (few weeks)

6. Replay Attack Prevention:
   - CSPRNG state update function: Incorporates current timestamp and Fox callsign
   - Ensures unique CSPRNG outputs for each 15-second time slot, even with repeated messages


#### 3.4.4 Implementation Notes

1. Caching Strategy: To optimize performance, the implementation includes a caching mechanism that stores precomputed CSPRNG states at regular intervals. This allows for efficient lookup of states for arbitrary timestamps within the DXpedition period.

2. Platform Compatibility: While the reference implementation is in Rust, the algorithm can be easily implemented in other languages.

#### 3.4.5 Open Questions and Future Considerations
1. Alternative Hash Functions: While BLAKE3 is chosen for its favorable properties, the impact of using more widely implemented alternatives like SHA-3 should be evaluated.
2. State Size Adjustments: As SuperFox itself is somewhat experimental, the possibility of increasing the state size if future SuperFox message formats allow for more bits should be considered.


### 3.5 BLS Signature Considerations

The choice of the elliptic curve for BLS signatures is crucial:

1. Signature Size: BLS signatures typically have a size approximately twice the security level in bits. The prototype Rust code uses the BN254 curve to demonstrate the mechanics of the BTO protocol. But the 256-bit signatures produced by this curve are slightly too large. We aim for a 200-bit signature to fit within the message constraints.

2. Security Level: The chosen curve should provide approximately 80-90 bits of security, balancing security requirements with signature/message size constraints.

3. Curve Selection: Further work is needed to identify the most appropriate elliptic curve that meets these requirements. We will likely use an existing parameterized family of curves or some other generation method from the literature.

### 3.6 Message Structure
**Standard message (i3 = 0):** Contains FoxCall, up to 9 HoundCalls, up to 4 signal reports, "MoreCQs" flag, a 20-bit digital signature, and a 3-bit message type.
```
F   H1  H2  H3  H4  H5  H6  H7  H8  H9  R6 R7 R8 R9 U  Q  D   M    Type
c28 c28 c28 c28 c28 c28 c28 c28 c28 c28 r5 r5 r5 r5 u5 q1 d20 i3=0 Std Msg
280 300 305 326 329
```
This message type already exists in the prototype SuperFox protocol. In the prototype, the 20-bit digital signature is based on a pre-shared secret corresponding to the DXpedition's callsign. In the BTO protocol, we


**Authentication Signature message w/ standard call (i3 = 4):** Contains standard 28-bit FoxCall, 15-bit grid locator, 56-bit RNG state, and approximately 185-bit BLS signature. The remaining ~45 bits are unused.
```
i3 = 4: Signed RNG State Message
-----------------------------------------------------------------------------
F   G   RN   D    U   M    Type
c28 g15 rn56 d185 u45 i3=4 Auth Sig Standard
28  43  99   284  329 
```
**Authentication Signature message w/ compound call (i3 = 5):** Contains a 58-bit compound FoxCall, 15-bit grid locator, 56-bit RNG state, and approximately 185-bit BLS signature. The remaining ~15 bits are unused.
```
i3 = 4: Signed RNG State Message
-----------------------------------------------------------------------------
FC  G   RN   D    U   M    Type
c58 g15 rn56 d185 u15 i3=5 Auth Sig Compound
58  73  129  314
```


```
--Legend--
D Digital signature (20 bits or ~185 bits (TBD))
RN Random number generator state (56 bits)
F Fox call (28 bits)
FC Compound Fox call (58 bits)
G Grid locator (15 bits)
H Hound call (28 bits)
M Message type (3 bits)
Q MoreCQs flag
R Report, (5 bits: -19 to +10 dB, or RR73)
T Free text, up to 26 characters total
U Unused bits
```

The two authentication signature message types (i3 = 4 and i3 = 5) are new. A compound callsign requires more bits than a standard one, so to ensure BTO supports both, the BLS signature size is chosen by assuming a compound callsign is used.

### 3.7 Validation Process

1. Hounds store received messages (both CQ and RRR) in a pending queue.
2. Upon receiving a CQ message:
    - Verify the BLS signature using the Fox's public key
    - Extract the CSPRNG state
    - Use the CSPRNG state to validate all pending RRR messages by recomputing and comparing the 20-bit hashes
3. Validated messages are moved from the pending queue to a validated message list
4. Messages that fail validation are discarded or flagged as potentially fraudulent in the UI

## 4. Code and Pseudo-code

< to be updated later>

## 5. Alternatives Considered

1. Fixed set of pre-generated keys
    - Pro: Keys can be "baked in" to software
    - Con: Lacks flexibility and requires periodic updates

2. Per-message digital signatures
    - Pro: Very high security
    - Pro: No impact from message loss, since the same signal report/acknoledgement message contains the digital signature
    - Con: Reduces QSO efficiency. If the signature is ~185-bits, that leaves only 144 bits for signal reports/acknowledgements out of the 329-bit total in a standard message.

## 6. Cross-cutting Concerns

### 6.1 Security

- The BN254 curve provides ~100 bits of security, but is slightly too large, so we need to find a smaller curve
- 20-bit hash per RRR message maintains low overhead while providing adequate security

### 6.2 Performance

- Expected time for a Hound to verify: 3.75 minutes (at 20% message loss)
- 95% chance of validation within 7.5 minutes (at 20% message loss)
- QSO throughput efficiency: ~90% (assuming 5-minute intervals for special authenticated state messages)

### 6.3 Compatibility

- Requires changes to existing SuperFox mode implementation to create two variants of an Authentication Signature message type

### 6.4 Key Distribution

The BTO protocol requires efficient and secure distribution of DXpedition public keys to Hound stations. We propose a dual approach to key distribution, catering to both internet-connected and offline scenarios.

#### 6.4.1 Hierarchical Key Structure

1. Root Keys:
   - WSJT-X developer keys and NCDXF (Northern California DX Foundation) keys serve as root keys.
   - These long-lived keys are baked into the WSJT-X software distribution.
   - Purpose: To sign and authenticate DXpedition-specific keys.

2. DXpedition Keys:
   - Generated for each specific DXpedition.
   - Short-lived: typically valid for a few weeks to months.
   - Signed by one or more root keys to establish a chain of trust.

#### 6.4.2 Automated Internet-based Distribution

1. GitHub Repository:
   - A dedicated GitHub repository serves as the central distribution point.
   - Leverages GitHub Pages for efficient static file hosting (up to ~100GB/month bandwidth). This is a highly reliable way to serve static data, is easy to read for humans, and is free for us.

2. Key Format and Storage:
   - Keys stored in JSON format with the following schema:
     ```json
     {
       "callsign": "DX1ABC",
       "expedition_name": "Bouvet Island DXpedition",
       "public_key": "base64_encoded_public_key_here",
       "start_date": "2024-01-15",
       "end_date": "2024-01-30",
       "signature": "base64_encoded_developer_signature_here"
     }
     ```
   - The `signature` field contains a digital signature from a WSJT-X developer or NCDXF key, signing all other fields in the JSON object.

3. Repository Structure:
   ```
   repository-root/
   ├── index.json
   ├── keys/
   │   ├── 2024/
   │   │   ├── 01/
   │   │   │   ├── dx1_callsign.json
   │   │   │   ├── dx2_callsign.json
   │   │   ├── 02/
   │   │   │   ├── dx3_callsign.json
   │   │   │   ├── dx4_callsign.json
   │   ├── 2025/
   │   │   ├── 01/
   │   │   │   ├── dx5_callsign.json
   | README.md
   | revocations.json
   ```

4. Updating Process:
   - New DXpedition keys: Add new JSON file in appropriate year/month directory.
   - Update `index.json` with metadata for the new key.
   - For modifications, update both individual key file and `index.json` entry.

5. Client (WSJT-X) Implementation:
   - On startup or periodically:
     a. Fetch and parse `index.json`.
     b. Compare against locally stored keys.
     c. Download any new or updated key files based on `file_path` and `last_updated` fields.
     d. Verify signatures and store new keys.

6. Revocation:
   - `revocations.json` lists all revoked keys with relevant metadata.
   - `index.json` includes a `revocation_status` for each key.
   - WSJT-X checks the revocation list during updates and modifies its local key store accordingly.
   - The `revocations.json` file is also signed by a WSJT-X developer key to prevent tampering.

#### 6.4.3 Manual Key Loading (Offline Method)

1. User Interface:
   - Implement a dedicated UI in WSJT-X for manual key entry.
   - Support loading from a set of JSON files (e.g., from a USB drive).

2. Key Format:
   - Use the same JSON format as in the automated method for consistency.

3. Verification:
   - WSJT-X verifies the signature using built-in root public keys upon manual entry.
   - Provides immediate feedback on key validity and expiration.

4. Storage:
   - Manually entered keys are stored in the same local database as automatically fetched keys.
   - UI allows users to view, delete, or update manually entered keys.

#### 6.4.4 Key Lifecycle Management

1. Key Generation:
   - DXpedition organizers generate their own key pair.
   - Public key is submitted to WSJT-X developers or NCDXF for signing.
   - Signed key is then distributed via the methods described in 9.4.2 and 9.4.3.

2. Key Validity Period:
   - Keys are tied to specific callsigns and expedition dates.
   - The JSON schema includes `start_date` and `end_date` fields to define the validity period.
   - WSJT-X clients should enforce these dates, rejecting messages signed with expired keys.

3. Key Expiration:
   - WSJT-X clients could check the expiration dates of stored keys on startup/update & mark them invalid.

4. Key Revocation:
   - Implement a revocation mechanism using the `revocations.json` file.
   - Revocations should be signed by WSJT-X developer keys to prevent unauthorized revocations.
   - WSJT-X clients should check for revocations periodically when online.
   - For offline operations, provide a manual method to update revocation status.

#### 6.4.5 Security Considerations

1. Root Key Protection:
   - WSJT-X developer and NCDXF root keys must be kept extremely secure.
   - In the basic scheme where we bake these in, a software update would be required to update them.

2. DXpedition Key Security/Verification
   - We only require that DXpeditions send us their public key, which we sign with the WSJT-X developer and NCDXF root keys.
   - With the BTO protocol, since only the signed public keys are used, there is no need for DXpeditions to transmit their private keys to anyone other than members of their team.
   - We could allow users to add keys not signed by our root keys, via the manual loading technique. The chance of this being used by pirates to "dupe" Hounds is low, but it keeps in the open spirit of amateur radio by leaving the door open for unaffiliated DXpeditions.
