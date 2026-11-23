# CHANGELOG

## [0.2.1] - 2026-11-23

### Changed

- Documentation: the background on Signal's work now separates PQXDH (2023, session setup) from SPQR (announced 2025), and says this crate uses a simplified form of the epoch design rather than the ML-KEM Braid.
- Crate description updated to match.
- The published package no longer includes CI configuration, fuzz targets or the social preview image.

## [0.2.0] - initial release

- Hybrid Double Ratchet: ML-KEM-768 + X25519, SCKA epoch model
- Adversarial test suite: replay attacks, skip cache exhaustion, cross-epoch out-of-order, session isolation
- cargo-fuzz targets for header decoding and state deserialization
- Criterion benchmarks for DH ratchet latency and within-epoch throughput
- MIRI UB detection in CI
- proptest property-based testing
- State serialization with versioned binary format (v1)
- Optional serde support
- Full zeroize coverage on all key material
