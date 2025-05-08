use criterion::{Criterion, criterion_group, criterion_main};
use qxvanity::{generator::Generator, wireguard::WireGuardGenerator};
use regex::RegexSet;
use std::hint;

pub fn benchmark(c: &mut Criterion) {
    let generator = WireGuardGenerator;
    let patterns = hint::black_box(RegexSet::new(["T3stP4tt3rn"]).unwrap());

    c.bench_function("generate_wireguard", |b| {
        b.iter(|| generator.generate_matching(&patterns, false))
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
