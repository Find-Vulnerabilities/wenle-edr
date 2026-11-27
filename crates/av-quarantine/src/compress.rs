//! Payload compression for the vault.
//!
//! # The header is the format
//!
//! A quarantined payload is either a packed one or one written before packing
//! existed, and the reader must tell them apart without an index field it cannot
//! add to old records. So a packed payload describes itself: the eight bytes
//! `WENLEQZ1`, then the original length as a little-endian `u64`, then a zstd
//! frame. Anything that does not begin with those bytes is returned unchanged,
//! which is exactly what an old record is.
//!
//! # The declared length is checked twice
//!
//! Once before decompression, against a hard ceiling, so a crafted header cannot
//! ask the machine for an allocation it will never fill; and once after, so a
//! payload whose frame is shorter or longer than it claims is an error rather
//! than a silently truncated file.
//!
//! # Small payloads are left alone
//!
//! Compression costs a header and a frame; below half a kilobyte, or when the
//! frame would not be smaller, the bytes are stored as they are. The vault is a
//! record of evidence, not an archive, and a format that inflates a 200-byte
//! script to prove it compresses is the wrong trade.

use crate::error::QuarantineError;

/// The bytes a packed payload starts with, and the version of the layout.
pub const MAGIC: &[u8; 8] = b"WENLEQZ1";

/// The largest payload a header may ask for, before the frame is even read.
pub const MAX_DECOMPRESSED: u64 = 4 * 1024 * 1024 * 1024;

const HEADER: usize = 16;

/// Compress a payload for storage, or return it as it is when packing would not
/// pay for itself.
pub fn pack(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 512 {
        return bytes.to_vec();
    }
    let compressed = match zstd::stream::encode_all(bytes, 3) {
        Ok(compressed) => compressed,
        Err(error) => {
            log::warn!("a payload was stored uncompressed: {error}");
            return bytes.to_vec();
        }
    };
    if compressed.len() + HEADER >= bytes.len() {
        return bytes.to_vec();
    }
    let mut packed = Vec::with_capacity(HEADER + compressed.len());
    packed.extend_from_slice(MAGIC);
    packed.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    packed.extend_from_slice(&compressed);
    packed
}

/// Undo [`pack`], for both formats.
pub fn unpack(stored: &[u8]) -> Result<Vec<u8>, QuarantineError> {
    if !stored.starts_with(MAGIC) {
        // Written before packing existed, or small enough that packing did not
        // pay. Both are the bytes themselves.
        return Ok(stored.to_vec());
    }
    if stored.len() < HEADER {
        return Err(QuarantineError::Other(
            "a packed payload ends inside its own header".to_string(),
        ));
    }
    let mut length = [0u8; 8];
    length.copy_from_slice(&stored[MAGIC.len()..HEADER]);
    let declared = u64::from_le_bytes(length);
    if declared > MAX_DECOMPRESSED {
        return Err(QuarantineError::Other(format!(
            "a packed payload declares {declared} bytes, above the {MAX_DECOMPRESSED} ceiling"
        )));
    }
    let bytes = zstd::stream::decode_all(&stored[HEADER..]).map_err(|error| {
        QuarantineError::Other(format!("a packed payload did not decompress: {error}"))
    })?;
    if bytes.len() as u64 != declared {
        return Err(QuarantineError::Other(format!(
            "a packed payload declared {declared} bytes and produced {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressible_bytes_round_trip_and_shrink() {
        let original = vec![b'A'; 64 * 1024];
        let packed = pack(&original);
        assert!(packed.starts_with(MAGIC));
        assert!(packed.len() < original.len());
        assert_eq!(unpack(&packed).unwrap(), original);
    }

    #[test]
    fn an_old_payload_without_a_header_is_returned_unchanged() {
        let old = b"an entry written before packing existed";
        assert_eq!(unpack(old).unwrap(), old.to_vec());
    }

    #[test]
    fn a_small_payload_is_stored_as_it_is() {
        let small = b"tiny";
        assert_eq!(pack(small), small.to_vec());
    }

    #[test]
    fn a_header_past_the_ceiling_is_refused_before_reading() {
        let mut packed = Vec::new();
        packed.extend_from_slice(MAGIC);
        packed.extend_from_slice(&u64::MAX.to_le_bytes());
        packed.extend_from_slice(b"not a frame");
        assert!(unpack(&packed).is_err());
    }

    #[test]
    fn a_truncated_frame_is_an_error_not_a_shorter_file() {
        let packed = pack(&vec![b'B'; 16 * 1024]);
        let cut = packed.len() - 8;
        assert!(unpack(&packed[..cut]).is_err());
    }

    #[test]
    fn a_frame_that_declares_the_wrong_length_is_refused() {
        let original = vec![b'C'; 32 * 1024];
        let mut packed = pack(&original);
        let wrong = (original.len() as u64 - 1).to_le_bytes();
        packed[8..16].copy_from_slice(&wrong);
        assert!(unpack(&packed).is_err());
    }
}
