extern crate core;
use std::ops::{Index, Sub};
use std::sync::Arc;

use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv, KeyInit, Nonce};
use aes_gcm_siv::aead::AeadMut;
use aes_gcm_siv::aead::generic_array::GenericArray;
use base64::Engine;
use bytebuffer::{ByteBuffer, Endian};
use futures::executor::block_on;
use lazy_static::lazy_static;
use math::set::traits::Finite;
use num_bigint::{BigInt, BigUint, Sign, ToBigInt, ToBigUint};
use num_modular::{ModularCoreOps, ModularPow, ModularUnaryOps};
use num_traits::{One, ToPrimitive, Zero};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SignatureAlgorithm};
use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{Certificate, ClientConfig, PrivateKey, ServerName};
use tokio_rustls::TlsConnector;

use crate::no_cert_verifier::NoVerifier;

mod utils;
mod no_cert_verifier;

lazy_static! {
    static ref CLIENT_NAME: Vec<u8> = utils::string_compat::get_bytes(String::from("adb pair client\u{0000}"));
    static ref SERVER_NAME: Vec<u8> = utils::string_compat::get_bytes(String::from("adb pair server\u{0000}"));
    static ref INFO: Vec<u8> = utils::string_compat::get_bytes(String::from("adb pairing_auth aes-128-gcm key"));
    static ref EXPORTED_KEY_LABEL: Vec<u8> =  utils::string_compat::get_bytes(String::from("adb-label\u{0000}"));
}
const HKDF_KEY_LENGTH: usize = 128 / 8;
const GCM_IV_LENGTH: usize = 12;

// Android Public Key
const ANDROID_PUBKEY_MODULUS_SIZE: usize = 2048 / 8;
const ANDROID_PUBKEY_ENCODED_SIZE: usize = 3 * 4 + 2 * ANDROID_PUBKEY_MODULUS_SIZE;
const ANDROID_PUBKEY_MODULUS_SIZE_WORDS: usize = ANDROID_PUBKEY_MODULUS_SIZE / 4;
const SIGNATURE_PADDING_AS_INT: [i32; 236] = [
    0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
    0x04, 0x14
];

lazy_static! {
    static ref RSA_SHA_PKCS1_SIGNATURE_PADDING: Vec<u8> = {
        let mut bytes = Vec::<u8>::with_capacity(SIGNATURE_PADDING_AS_INT.len());
        for i in SIGNATURE_PADDING_AS_INT.iter() {
            bytes.push(*i as u8);
        }
        bytes
    };
}

// PeerInfo
const MAX_PEER_INFO_SIZE: usize = 1 << 13;
const ADB_RSA_PUB_KEY: u8 = 0;
const ADB_DEVICE_GUID: u8 = 0;

// PairingPacketHeader
const CURRENT_KEY_HEADER_VERSION: u8 = 1;
const MIN_SUPPORTED_KEY_HEADER_VERSION: u8 = 1;
const MAX_SUPPORTED_KEY_HEADER_VERSION: u8 = 1;
const MAX_PAYLOAD_SIZE: usize = 2 * MAX_PEER_INFO_SIZE;
const PAIRING_PACKET_HEADER_SIZE: u8 = 6;
const SPAKE2_MSG: u8 = 0;
const PEER_INFO: u8 = 1;

struct PairingPacketHeader {
    packet_version: u8,
    packet_type: u8,
    packet_payload_size: i32,
}

struct PeerInfo {
    peer_type: u8,
    peer_data: Vec<u8>,
}

fn big_endian_to_little_endian_padded(len: usize, in_val: &BigUint) -> Option<Vec<u8>> {
    let mut out = vec![0u8; len];
    let bytes = in_val.to_bytes_be();
    let num_bytes = bytes.len();
    if len < num_bytes {
        if !fits_in_bytes(&bytes, num_bytes, len) {
            return None;
        }
    }
    let num_bytes = std::cmp::min(num_bytes, len);
    out[0..num_bytes].copy_from_slice(&bytes[0..num_bytes]);
    Some(out)
}

fn fits_in_bytes(bytes: &[u8], num_bytes: usize, len: usize) -> bool {
    let mut mask = 0u8;
    for i in len..num_bytes {
        mask |= bytes[i];
    }
    mask == 0u8
}

async fn adb_pairing(ip: &str, port: u16, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    let public_key: RsaPublicKey;
    {
        let mut cert_param = CertificateParams::new(vec![]);
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Antagonism");
        cert_param.distinguished_name = distinguished_name;
        cert_param.alg = &rcgen::PKCS_RSA_SHA256;
        let keypair = KeyPair::try_from(private_key.to_pkcs8_der()?.as_bytes())?;
        cert_param.key_pair = Option::Some(keypair);
        let rsa_cert = rcgen::Certificate::from_params(cert_param).unwrap();
        let public_key_pem = rsa_cert.get_key_pair().public_key_pem();
        public_key = RsaPublicKey::from_public_key_pem(public_key_pem.as_str()).expect("Wrong public key");
    }

    let public_key = rsa::RsaPublicKey::from_public_key_pem();

    //println!("Modulus: {}", public_key.n());
    // Setup TCP TLS connection
    let client_cert = rcgen::generate_simple_self_signed(vec!["Antagonism".to_string()]).unwrap();
    let stream = TcpStream::connect((ip, port)).await?;
    let config = ClientConfig::builder()
        .with_cipher_suites(&[tokio_rustls::rustls::cipher_suite::TLS13_AES_256_GCM_SHA384])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .unwrap()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_single_cert(
            vec![Certificate(client_cert.serialize_der().unwrap())],
            PrivateKey(client_cert.serialize_private_key_der()),
        ).expect("Bad cert!");

    let connector = TlsConnector::from(Arc::new(config));
    let mut stream = connector.connect(ServerName::try_from(ip).unwrap(), stream).await.expect("Connection error");

    let mut pass_buffer = ByteBuffer::new();
    {
        let client_connection = stream.get_mut().1;
        let mut key_material: [u8; 64] = [0; 64];
        key_material = client_connection
            .export_keying_material(key_material, EXPORTED_KEY_LABEL.to_vec().as_slice(), None)?;
        pass_buffer.resize(password.as_bytes().len() + key_material.len());
        pass_buffer.write_bytes(password.as_bytes());
        pass_buffer.write_bytes(&key_material);
    }

    let (spake25519, msg) = Spake2::<Ed25519Group>::start_a(
        &Password::new(pass_buffer.into_vec()),
        &Identity::new(CLIENT_NAME.as_ref()),
        &Identity::new(SERVER_NAME.as_ref()),
    );

    let mut packet = PairingPacketHeader {
        packet_version: CURRENT_KEY_HEADER_VERSION,
        packet_type: SPAKE2_MSG,
        packet_payload_size: msg.size() as i32,
    };

    println!("Sent packet payload size: {}", packet.packet_payload_size);

    // Write out header
    {
        let mut buffer = ByteBuffer::new();
        buffer.resize(PAIRING_PACKET_HEADER_SIZE as usize);
        buffer.set_endian(bytebuffer::Endian::BigEndian);
        buffer.write_bytes(&[packet.packet_version, packet.packet_type]);
        buffer.write_bytes(&packet.packet_payload_size.to_be_bytes());
        stream.write(buffer.as_bytes()).await?;
        stream.write(msg.as_slice()).await?;
    }

    // Read in header
    {
        let mut buffer = vec!(0u8; PAIRING_PACKET_HEADER_SIZE as usize);
        stream.read_exact(buffer.as_mut_slice()).await?;
        let mut buffer = ByteBuffer::from(buffer);
        buffer.set_endian(Endian::BigEndian);

        let packet_version = buffer.read_u8().unwrap();
        let packet_type = buffer.read_u8().unwrap();
        let packet_payload_size = buffer.read_i32().unwrap();
        if packet_version < MIN_SUPPORTED_KEY_HEADER_VERSION || packet_version > MAX_SUPPORTED_KEY_HEADER_VERSION {
            println!("PairingPacketHeader version mismatch (us={} them={})", CURRENT_KEY_HEADER_VERSION, packet_version);
        }
        if packet_type != SPAKE2_MSG && packet_type != PEER_INFO {
            println!("Unknown PairingPacket type {}", packet_type);
        }
        if packet_payload_size <= 0 || packet_payload_size > MAX_PAYLOAD_SIZE as i32 {
            println!("Header payload not within a safe payload size (size={})", packet_payload_size);
        }
        packet = PairingPacketHeader {
            packet_version,
            packet_type,
            packet_payload_size,
        }
    }

    if packet.packet_type != SPAKE2_MSG {
        panic!("Unexpected header type!")
    }
    println!("Received packet size: {}", packet.packet_payload_size);

    // Read the SPAKE2 msg payload and initialize the cipher for encrypting the PeerInfo and certificate.
    let mut their_msg = vec![0u8; (packet.packet_payload_size) as usize];
    println!("length: {}", their_msg.len());
    stream.read_exact(their_msg.as_mut_slice()).await?;
    their_msg.insert(0, 0x42);
    let key_material = spake25519.finish(their_msg.as_mut_slice()).expect("Spake2 decryption error!");
    let mut secret_key = [0u8; HKDF_KEY_LENGTH];
    let hk = hkdf::Hkdf::<Sha256>::new(None, key_material.as_slice());
    hk.expand(&[], &mut secret_key).expect("Error in generating hkdf bytes");

    // Start exchanging peer info
    let peer_info: PeerInfo;
    {
        let key_size = 4 * ((ANDROID_PUBKEY_ENCODED_SIZE as f32 / 3.0).ceil() as usize);

        // Prepare the final stream
        let mut out_stream = ByteBuffer::new();
        out_stream.resize(key_size + "Antagonism".len() + 2);

        if public_key.n().to_bytes_be().len() < ANDROID_PUBKEY_MODULUS_SIZE {
            panic!("Invalid RSA key length");
        }
        let mut key_struct = ByteBuffer::new();
        key_struct.resize(ANDROID_PUBKEY_ENCODED_SIZE);
        key_struct.set_endian(Endian::LittleEndian);
        key_struct.write_i32(ANDROID_PUBKEY_MODULUS_SIZE_WORDS as i32);
        let mut r32: BigUint = Zero::zero();
        let mut n0inv: BigUint = Zero::zero();
        let mut rr: BigUint = Zero::zero();

        let public_key_modulus: BigUint = BigUint::from_bytes_be(public_key.n().to_bytes_be().as_slice());

        r32.set_bit(32, true);
        println!("r32: {:?}", r32);
        println!("{:?}", public_key_modulus);
        n0inv = public_key_modulus.modpow(
            &1.to_biguint().unwrap(), &r32,
        );

        println!("n0inv before inversemod: {:?}", n0inv);
        n0inv = n0inv.invm(&r32).unwrap();
        println!("n0inv after inversemod: {:?}", n0inv);
        n0inv = r32.sub(n0inv);
        println!("n0inv after subtraction: {:?}", n0inv);
        let n0inv = n0inv.to_u32().unwrap();
        key_struct.write_u32(n0inv);

        // Store the modulus
        key_struct.write_bytes(big_endian_to_little_endian_padded(ANDROID_PUBKEY_MODULUS_SIZE, &public_key_modulus).unwrap().as_slice());

        // Compute and store rr = (2^(rsa_size)) ^ 2 mod N
        rr.set_bit((ANDROID_PUBKEY_MODULUS_SIZE * 8) as u64, true);
        rr = rr.powm(&2.to_biguint().unwrap(), &public_key_modulus);
        key_struct.write_bytes(big_endian_to_little_endian_padded(ANDROID_PUBKEY_MODULUS_SIZE, &rr).unwrap().as_slice());

        // Store the exponent
        key_struct.write_i32(public_key.e().to_i32().unwrap());
        key_struct.as_bytes();

        let base64_encoded = base64::engine::general_purpose::STANDARD.encode(key_struct.as_bytes());
        println!("{:?}", base64_encoded);
        out_stream.write_bytes(base64_encoded.as_bytes());
        out_stream.write_bytes(utils::string_compat::get_bytes(String::from(" Antagonism\u{0000}")).as_ref());
        let mut peer_data = out_stream.into_vec();
        peer_data.resize(MAX_PEER_INFO_SIZE - 1, 0);

        peer_info = PeerInfo {
            peer_type: ADB_RSA_PUB_KEY,
            peer_data,
        }
    }


    // Start encrypt / decrypt operations
    let mut encrypt_iv = 0i64;
    let mut decrypt_iv = 0i64;
    {
        let mut buffer = ByteBuffer::new();
        buffer.resize(MAX_PEER_INFO_SIZE);
        buffer.set_endian(Endian::BigEndian);
        buffer.write_u8(peer_info.peer_type);
        buffer.write_bytes(peer_info.peer_data.as_slice());
        //aes_gcm_siv::Key::new_from_slice(&secret_key).expect("GCM Key error");
        let aes_key = aes_gcm_siv::Key::<Aes128GcmSiv>::from_slice(&secret_key);
        let mut cipher = Aes128GcmSiv::new(&aes_key);

        let mut iv_buffer = ByteBuffer::new();
        iv_buffer.resize(GCM_IV_LENGTH);
        iv_buffer.set_endian(Endian::LittleEndian);
        iv_buffer.write_i64(encrypt_iv);
        encrypt_iv += 1;

        let nonce = Nonce::from_slice(iv_buffer.as_bytes());
        let encrypted_buffer = cipher.encrypt(nonce, buffer.as_bytes()).expect("Encrypt peer info buffer error!");

        packet = PairingPacketHeader {
            packet_version: CURRENT_KEY_HEADER_VERSION,
            packet_type: PEER_INFO,
            packet_payload_size: encrypted_buffer.len() as i32,
        };


        // Write out header
        let mut buffer = ByteBuffer::new();
        buffer.resize(PAIRING_PACKET_HEADER_SIZE as usize);
        buffer.set_endian(bytebuffer::Endian::BigEndian);
        buffer.write_bytes(&[packet.packet_version, packet.packet_type]);
        buffer.write_bytes(&packet.packet_payload_size.to_be_bytes());
        stream.write(buffer.as_bytes()).await?;
        stream.write(msg.as_slice()).await?;
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let ip = "192.168.31.150";
    let port = 40685;
    let password = "077906";

//    adb_pairing(ip, port, password);

    block_on(async {
        match adb_pairing(ip, port, password).await {
            Ok(_) => println!("Pairing successful!"),
            Err(e) => panic!("Error: {:?}", e),
        }
    });
}
