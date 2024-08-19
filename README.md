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
          Probability of a Hound failing to decode a message sent by the Fox [default: 0.2]
  -c, --callsign <CALLSIGN>
          Callsign of the Fox station [default: N5J]
  -n, --num-periods-to-simulate <NUM_PERIODS_TO_SIMULATE>
          Number of 15 second time periods to simulate [default: 90]
  -n, --num-final-cq-messages <NUM_FINAL_CQ_MESSAGES>
          Number of CQ messages a Fox should send at the end of a session [default: 3]
  -h, --help
          Print help
  -V, --version
          Print version
```
