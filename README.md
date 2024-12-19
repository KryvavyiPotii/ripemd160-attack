# ripemd160-attack

A simple CLI application that executes brute-force, birthdays and Hellman's attacks on RIPEMD-160 hash.

## Usage

```console
$ ripemd160-attack help
Execute various attacks on RIPEMD-160 hash.

Usage: ripemd160-attack [OPTIONS] [COMMAND]

Commands:
  bruteforce  Execute brute-force attack
  birthdays   Execute birthdays attack
  hellman     Execute Hellman's attack or generates preprocessing table
  help        Print this message or the help of the given subcommand(s)

Options:
  -m, --message <message>
          Message to process [default: "Some huge message"]
      --tr <message transform>
          Type of message transformation [default: random_number] [possible values: random_number, number_in_sequence, mutate]
  -s, --hash-size <hash size>
          Size of the hash suffix in bytes that will be attacked [default: 2]
  -p, --probability <success probability>
          Expected success probability [default: 0.95]
      --verbose-tries <verbose tries>
          Number of tries that will be printed out [default: 30]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Extra

Python 3 script `to_table.py` is also added to the project for converting obtained data into a LaTeX or text table with 2 columns:
1. Attack number (`att`)
2. Iteration count (`iter`) - number of iterations during the attack

It accepts path to directory with output files and the type of a table to create.
