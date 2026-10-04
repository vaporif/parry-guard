use bytes::BytesMut;
use parry_guard_daemon::protocol::DaemonCodec;
use proptest::prelude::*;
use tokio_util::codec::Decoder;

proptest! {
    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut buf = BytesMut::from(bytes.as_slice());
        let _ = DaemonCodec.decode(&mut buf);
    }
}
