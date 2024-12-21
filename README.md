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

```console
$ ripemd160-attack hellman help
Execute Hellman's attack or generates preprocessing table

Usage: ripemd160-attack hellman [OPTIONS] [COMMAND]

Commands:
  generate  Generate preprocessing tables
  convert   Convert preprocessing tables into different format
  execute   Execute Hellman's attack
  help      Print this message or the help of the given subcommand(s)

Options:
  -d, --table-dir <table directory>    Path to table directory [default: tables]
      --rsize <reduction output size>  Reduction function output size in bytes [default: 16]
      --chain-num <chain number>       Number of table chains [default: 16384]
      --chain-len <chain length>       Length of table chains [default: 128]
  -h, --help                           Print help
```

```console
$ ripemd160-attack hellman execute --help
Execute Hellman's attack

Usage: ripemd160-attack hellman execute [OPTIONS]

Options:
      --format <table file format>
          Table file format to read/write [default: bin] [possible values: json, bin]
      --tables <table number>
          Number of tables to process [default: 1]
      --mem-tables <table in process memory number>
          Number of tables in process memory [default: 1]
  -h, --help
          Print help
```

```console
$ ripemd160-attack hellman generate --help
Generate preprocessing tables

Usage: ripemd160-attack hellman generate [OPTIONS]

Options:
      --format <table file format>  Table file format to read/write [default: bin] [possible values: json, bin]
      --tables <table number>       Number of tables to generate [default: 1]
  -h, --help                        Print help
```

```console
$ ripemd160-attack hellman convert --help
Convert preprocessing tables into different format

Usage: ripemd160-attack hellman convert [OPTIONS]

Options:
      --if <input format>    Format of input table file [possible values: json, bin]
      --of <output format>   Format of output table file [possible values: json, bin]
  -i, --index <table index>  Index of table to convert (number after '_' in file name)
  -f, --force                Overwrite existing tables that have the same index
  -h, --help                 Print help
```
