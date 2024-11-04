use std::{env, process};

pub mod hashattacks;

use hashattacks::*;


fn main() {
    let args = env::args();

    let config = AttackConfig::build(args).unwrap_or_else(|err| {
        println!("Problem parsing arguments: {err}");
        process::exit(1);
    });
   
    attack(config);
}


