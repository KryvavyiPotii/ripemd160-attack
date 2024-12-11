# ripemd160-attack

A simple CLI application that executes preimage search and birthdays attack on a part of RIPEMD-160 hash.

## Usage

```console
$ ripemd160-attack --help
Executes various attacks on RIPEMD160 hash.

Usage: ripemd160-attack [OPTIONS] [COMMAND]

Commands:
  bruteforce  Executes brute-force attack.
  birthdays   Executes birthdays attack.
  hellman     Executes Hellman's attack.
  help        Print this message or the help of the given subcommand(s)

Options:
  -m, --message <message>
          Initial message to process. [default: "Some huge message"]
  -t, --message-transform <message transform>
          Type of message modification. [default: random_number] [possible values: random_number, number_in_sequence, mutate]
  -s, --hash-size <hash size>
          Size of the hash suffix in bytes that will be attacked.
  -p, --probability <success probability>
          Expected success probability.
      --verbose-tries <verbose tries>
          Number of tries that will be outputted.
  -h, --help
          Print help
  -V, --version
          Print version
```

```console
$ ripemd160-attack bruteforce --help
Executes brute-force attack.

Usage: ripemd160-attack bruteforce

Options:
  -h, --help  Print help
```

```console
$ ripemd160-attack birthdays --help
Executes birthdays attack.

Usage: ripemd160-attack birthdays

Options:
  -h, --help  Print help
```

```console
$ ripemd160-attack birthdays --help
Executes birthdays attack.

Usage: ripemd160-attack birthdays

Options:
  -h, --help  Print help
```

```console
$ ripemd160-attack hellman --help
Executes Hellman's attack.

Usage: ripemd160-attack hellman [OPTIONS]

Options:
      --rsize <redundancy output size>               Redundancy function output size in bytes.
      --tables <hellman table number>                Number of tables.
      --stored-tables <hellman stored table number>  Number of tables written to disk.
      --vars <hellman table variable number>         Number of table variables.
      --iters <hellman table iteration count>        Number of table iterations.
  -h, --help                                         Print help
```

## Extra

Python 3 script `to_table.py` is also added to the project for converting obtained data into a LaTeX or text table with 2 columns:
1. Attack number (`att`)
2. Iteration count (`iter`) - number of iterations during the attack

It accepts path to directory with output files and the type of a table to create.
