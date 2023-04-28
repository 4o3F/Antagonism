use bytes::Bytes;

pub fn get_bytes(text: String) -> Vec<u8> {
    bytes::Bytes::from(text).to_vec()
}