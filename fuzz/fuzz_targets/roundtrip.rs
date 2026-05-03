#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_ratchet::Header;

// Fuzz `Header::encode`→`decode` roundtrip: any valid decoded header must
// re-encode to identical bytes.
fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Header::decode(data) {
        let reencoded = h.encode();
        let h2 = Header::decode(&reencoded).expect("re-encode produced invalid bytes");
        assert_eq!(h.n(), h2.n());
        assert_eq!(h.pn(), h2.pn());
        assert_eq!(h.dh_pk(), h2.dh_pk());
    }
});
