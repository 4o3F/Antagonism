use bytes::Bytes;
use spake2::{Ed25519Group, Identity, Password, Spake2};

const CLIENT_NAME: Bytes = crate::utils::string_compat::get_bytes(String::from("adb pair client\u{0000}"));
const SERVER_NAME: Bytes = crate::utils::string_compat::get_bytes(String::from("adb pair server\u{0000}"));
const INFO: Bytes = crate::utils::string_compat::get_bytes(String::from("adb pairing_auth aes-128-gcm key"));
const HKDF_KEY_LENGTH: i32 = 128 / 8;
const GCM_IV_LENGTH: i32 = 12;

struct PairingAuthContext {
    m_msg: Bytes,
    m_spake2_context: spake2::Spake2<Ed25519Group>,
}

impl PairingAuthContext {
    pub fn create_alice(password: Bytes) -> PairingAuthContext {
        let (spake25519, msg) = spake2::Spake2::<Ed25519Group>::start_a(
            &Password::new(password),
            &Identity::new(CLIENT_NAME.as_ref()),
            &Identity::new(SERVER_NAME.as_ref()),
        );
        PairingAuthContext {
            m_msg: Bytes::from(msg),
            m_spake2_context: spake25519,
        }
    }

    pub fn create_bob(password: Bytes) -> PairingAuthContext {
        let (spake25519, msg) = spake2::Spake2::<Ed25519Group>::start_b(
            &Password::new(password),
            &Identity::new(CLIENT_NAME.as_ref()),
            &Identity::new(SERVER_NAME.as_ref()),
        );
        PairingAuthContext {
            m_msg: Bytes::from(msg),
            m_spake2_context: spake25519,
        }
    }

}