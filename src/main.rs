mod args;

use args::{Args, Kind};
use clap::Parser;
use log::LevelFilter;
use qxvanity::{
    generator::{Generator, PrivateKey, PublicKey},
    ssh_ed25519::SshEd25519Generator,
    wireguard::WireGuardGenerator,
};
use rayon::ThreadPoolBuilder;
use regex::RegexSet;
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};
use thousands::Separable;

struct GeneratorParams<'a> {
    patterns: &'a RegexSet,
    status_interval: Duration,
    threads: usize,
    count: u64,
}

fn generate<G, S, P>(generator: &G, params: GeneratorParams)
where
    G: Generator<PrivateKey = S, PublicKey = P> + Sync,
    S: PrivateKey + Send,
    P: PublicKey + Send,
{
    let mut pool = ThreadPoolBuilder::new();

    if params.threads != 0 {
        pool = pool.num_threads(params.threads);
    }

    let pool = pool.build().unwrap();
    let (tx, rx) = mpsc::channel();

    pool.in_place_scope(|scope| {
        scope.spawn_broadcast(|_, _| {
            while tx
                .send(generator.generate_matching(params.patterns))
                .is_ok()
            {}
        });

        process_results(rx.iter(), params);
        drop(rx);
    });
}

fn process_results<I, S, P>(results: I, params: GeneratorParams)
where
    I: Iterator<Item = Option<(S, P)>>,
    S: PrivateKey,
    P: PublicKey,
{
    let status_interval = params.status_interval;
    let mut start = Instant::now();
    let mut interval_count: u64 = 0;
    let mut total_checked: u64 = 0;
    let mut found = 0;

    for key in results {
        if !status_interval.is_zero() {
            total_checked += 1;

            if start.elapsed() < status_interval {
                interval_count += 1;
            } else {
                log::info!(
                    "Speed: {} keys/s, checked {} keys, found {}",
                    (interval_count / status_interval.as_secs())
                        .separate_with_spaces(),
                    total_checked.separate_with_spaces(),
                    found.separate_with_spaces()
                );

                start = Instant::now();
                interval_count = 0;
            }
        }

        if let Some((private, public)) = key {
            log::info!("Found a matching keypair");
            let enc_private = private.to_canonical_key_string();
            let enc_public = public.to_canonical_key_string();
            println!("private:");
            println!("{enc_private}");
            println!();
            println!("public:");
            println!("{enc_public}");
            found += 1;

            if found == params.count {
                break;
            }
        }
    }
}

fn main() {
    let mut args = Args::parse();
    env_logger::builder().filter_level(LevelFilter::Info).init();

    if !args.status_interval.is_zero() {
        args.status_interval =
            Duration::from_secs(args.status_interval.as_secs().max(1));
    }

    let patterns =
        RegexSet::new(args.patterns.into_iter().map(|x| x.to_string()))
            .unwrap();

    let params = GeneratorParams {
        patterns: &patterns,
        status_interval: args.status_interval,
        threads: args.threads,
        count: args.count,
    };

    match args.kind {
        Kind::WireGuard => {
            generate(&WireGuardGenerator, params);
        }
        Kind::SshEd25519 => {
            generate(&SshEd25519Generator, params);
        }
    }
}
