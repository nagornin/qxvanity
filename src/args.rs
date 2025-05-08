use std::{num::ParseIntError, time::Duration};

use clap::{Parser, ValueEnum};
use humantime::DurationError;
use regex::Regex;

fn parse_status_interval(s: &str) -> Result<Duration, DurationError> {
    s.parse()
        .map(Duration::from_secs)
        .or_else(|_| humantime::parse_duration(s))
}

fn parse_num_threads(s: &str) -> Result<usize, ParseIntError> {
    if s == "auto" { Ok(0) } else { s.parse() }
}

#[derive(Parser)]
pub struct Args {
    #[arg(short = 't', long = "type", help = "Type of keypair to generate")]
    pub kind: Kind,
    #[arg(required = true, help = "Regex patterns to search public keys for")]
    pub patterns: Vec<Regex>,
    #[arg(
        short,
        long,
        value_parser = parse_status_interval,
        default_value = "5s",
        help = "Print search status with this interval, 0 to never print"
    )]
    pub status_interval: Duration,
    #[arg(
        short,
        long,
        default_value_t = 1,
        help = "Number of matching keypairs to generate, 0 to keep generating forever"
    )]
    pub count: u64,
    #[arg(
        short = 'p',
        long,
        default_value = "auto",
        value_parser = parse_num_threads,
        help = "Number of threads"
    )]
    pub threads: usize,
    #[arg(
        short = 'k',
        long = "match-key-material",
        help = "Only match the actual key material, ignore any metadata"
    )]
    pub match_key_material: bool,
}

#[derive(ValueEnum, Clone)]
pub enum Kind {
    #[clap(name = "wireguard")]
    WireGuard,
    SshEd25519,
}
