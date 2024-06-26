mod protocol;

extern crate core;

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use std::io::{BufRead, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const EXPORTED_KEY_LABEL: &str = "adb-label\u{0}";
const CLIENT_NAME: &str = "adb pair client\u{0}";
const SERVER_NAME: &str = "adb pair server\u{0}";
const MAX_PEER_INFO_SIZE: i32 = 1 << 13;

const ANDROID_PUBKEY_MODULUS_SIZE: i32 = 2048 / 8;
const ANDROID_PUBKEY_ENCODED_SIZE: i32 = 3 * 4 + 2 * ANDROID_PUBKEY_MODULUS_SIZE;
const ANDROID_PUBKEY_MODULUS_SIZE_WORDS: i32 = ANDROID_PUBKEY_MODULUS_SIZE / 4;

fn generate_cert() -> anyhow::Result<(
    boring::x509::X509,
    boring::pkey::PKey<boring::pkey::Private>,
)> {
    let rsa = boring::rsa::Rsa::generate(2048).context("failed to generate rsa keypair")?;
    // put it into the pkey struct
    let pkey = boring::pkey::PKey::from_rsa(rsa)
        .context("failed to create pkey struct from rsa keypair")?;

    // make a new x509 certificate with the pkey we generated
    let mut x509builder = boring::x509::X509::builder().context("failed to make x509 builder")?;
    x509builder
        .set_version(2)
        .context("failed to set x509 version")?;

    // set the serial number to some big random positive integer
    let mut serial = boring::bn::BigNum::new().context("failed to make new bignum")?;
    serial
        .rand(32, boring::bn::MsbOption::ONE, false)
        .context("failed to generate random bignum")?;
    let serial = serial
        .to_asn1_integer()
        .context("failed to get asn1 integer from bignum")?;
    x509builder
        .set_serial_number(&serial)
        .context("failed to set x509 serial number")?;

    // call fails without expiration dates
    // I guess they are important anyway, but still
    let not_before = boring::asn1::Asn1Time::days_from_now(0)
        .context("failed to parse 'notBefore' timestamp")?;
    let not_after = boring::asn1::Asn1Time::days_from_now(360)
        .context("failed to parse 'notAfter' timestamp")?;
    x509builder
        .set_not_before(&not_before)
        .context("failed to set x509 start date")?;
    x509builder
        .set_not_after(&not_after)
        .context("failed to set x509 expiration date")?;

    // add the issuer and subject name
    // it's set to "/CN=LinuxTransport"
    // if we want we can make that configurable later
    let mut x509namebuilder =
        boring::x509::X509Name::builder().context("failed to get x509name builder")?;
    x509namebuilder
        .append_entry_by_text("CN", "LinuxTransport")
        .context("failed to append /CN=LinuxTransport to x509name builder")?;
    let x509name = x509namebuilder.build();
    x509builder
        .set_issuer_name(&x509name)
        .context("failed to set x509 issuer name")?;
    x509builder
        .set_subject_name(&x509name)
        .context("failed to set x509 subject name")?;

    // set the public key
    x509builder
        .set_pubkey(&pkey)
        .context("failed to set x509 pubkey")?;

    // it also needs several extensions
    // in the openssl configuration file, these are set when generating certs
    //     basicConstraints=CA:true
    //     subjectKeyIdentifier=hash
    //     authorityKeyIdentifier=keyid:always,issuer
    // that means these extensions get added to certs generated using the
    // command line tool automatically. but since we are constructing it, we
    // need to add them manually.
    // we need to do them one at a time, and they need to be in this order
    // let conf = boring::conf::Conf::new(boring::conf::ConfMethod::).context("failed to make new conf struct")?;
    // it seems like everything depends on the basic constraints, so let's do
    // that first.
    let bc = boring::x509::extension::BasicConstraints::new()
        .ca()
        .build()
        .context("failed to build BasicConstraints extension")?;
    x509builder
        .append_extension(bc)
        .context("failed to append BasicConstraints extension")?;

    // the akid depends on the skid. I guess it copies the skid when the cert is
    // self-signed or something, I'm not really sure.
    let skid = {
        // we need to wrap these in a block because the builder gets borrowed away
        // from us
        let ext_con = x509builder.x509v3_context(None, None);
        boring::x509::extension::SubjectKeyIdentifier::new()
            .build(&ext_con)
            .context("failed to build SubjectKeyIdentifier extention")?
    };
    x509builder
        .append_extension(skid)
        .context("failed to append SubjectKeyIdentifier extention")?;

    // now that the skid is added we can add the akid
    let akid = {
        let ext_con = x509builder.x509v3_context(None, None);
        boring::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .issuer(false)
            .build(&ext_con)
            .context("failed to build AuthorityKeyIdentifier extention")?
    };
    x509builder
        .append_extension(akid)
        .context("failed to append AuthorityKeyIdentifier extention")?;

    // self-sign the certificate
    x509builder
        .sign(&pkey, boring::hash::MessageDigest::sha256())
        .context("failed to self-sign x509 cert")?;

    let x509 = x509builder.build();

    Ok((x509, pkey))
}

fn vec_to_hex(bytes: &Vec<u8>) -> String {
    bytes.iter().map(|&data| format!("{:02x}", data)).collect()
}

fn big_endian_to_little_endian_padded(
    len: usize,
    num: boring::bn::BigNum,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut out = vec![0u8; len];
    let bytes = swap_endianness(num.to_vec());
    let mut num_bytes = bytes.len();
    if len < num_bytes {
        if !fit_in_bytes(bytes.as_ref(), num_bytes, len) {
            return Err(anyhow!("Can't fit in bytes"));
        }
        num_bytes = len;
    }
    out[..num_bytes].copy_from_slice(&bytes[..num_bytes]);
    return Ok(out);
}

fn fit_in_bytes(bytes: &Vec<u8>, num_bytes: usize, len: usize) -> bool {
    let mut mask = 0u8;
    for i in len..num_bytes {
        mask |= bytes[i];
    }
    return mask == 0;
}

fn swap_endianness(bytes: Vec<u8>) -> Vec<u8> {
    bytes.into_iter().rev().collect()
}

pub fn encode_rsa_publickey(
    public_key: boring::rsa::Rsa<boring::pkey::Public>,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut r32: boring::bn::BigNum;
    let mut n0inv: boring::bn::BigNum;
    let mut rr: boring::bn::BigNum;

    let mut tmp: boring::bn::BigNum;

    let mut ctx = boring::bn::BigNumContext::new().unwrap();

    if (public_key.n().to_vec().len() as i32) < ANDROID_PUBKEY_MODULUS_SIZE {
        return Err(anyhow!(
            String::from("Invalid key length ")
                + public_key.n().to_vec().len().to_string().as_str()
        ));
    }

    let mut key_struct = bytebuffer::ByteBuffer::new();
    key_struct.resize(ANDROID_PUBKEY_ENCODED_SIZE as usize);
    key_struct.set_endian(bytebuffer::Endian::LittleEndian);
    key_struct.write_i32(ANDROID_PUBKEY_MODULUS_SIZE_WORDS);

    // Compute and store n0inv = -1 / N[0] mod 2 ^ 32
    r32 = boring::bn::BigNum::new().unwrap();
    r32.set_bit(32).unwrap();
    n0inv = public_key.n().to_owned().unwrap();
    tmp = n0inv.to_owned().unwrap();
    // do n0inv mod r32
    n0inv
        .checked_rem(tmp.as_mut(), r32.as_ref(), ctx.as_mut())
        .unwrap();
    tmp = n0inv.to_owned().unwrap();
    n0inv
        .mod_inverse(tmp.as_mut(), r32.as_ref(), ctx.as_mut())
        .unwrap();
    tmp = n0inv.to_owned().unwrap();
    n0inv.checked_sub(r32.as_ref(), tmp.as_mut()).unwrap();
    // This is hacky.....
    key_struct.write_i32(n0inv.to_dec_str().unwrap().parse::<i32>().unwrap());

    key_struct
        .write(
            big_endian_to_little_endian_padded(
                ANDROID_PUBKEY_MODULUS_SIZE as usize,
                public_key.n().to_owned().unwrap(),
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();

    rr = boring::bn::BigNum::new().unwrap();
    rr.set_bit(ANDROID_PUBKEY_MODULUS_SIZE * 8).unwrap();
    tmp = rr.to_owned().unwrap();
    rr.mod_sqr(
        tmp.as_ref(),
        public_key.n().to_owned().unwrap().as_ref(),
        ctx.as_mut(),
    )
    .unwrap();

    key_struct
        .write(
            big_endian_to_little_endian_padded(
                ANDROID_PUBKEY_MODULUS_SIZE as usize,
                rr.to_owned().unwrap(),
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();

    println!("{:?}", public_key.e().to_string().parse::<i32>().unwrap());
    key_struct.write_i32(public_key.e().to_string().parse::<i32>().unwrap());

    Ok(key_struct.into_vec())
}

fn encode_rsa_publickey_with_name(
    public_key: boring::rsa::Rsa<boring::pkey::Public>,
) -> Result<Vec<u8>, anyhow::Error> {
    let name = " Antagonism\u{0}";
    let pkey_size = 4 * (f64::from(ANDROID_PUBKEY_ENCODED_SIZE) / 3.0).ceil() as usize;
    let mut bos = bytebuffer::ByteBuffer::new();
    bos.resize(pkey_size + name.len());
    let base64 = boring::base64::encode_block(encode_rsa_publickey(public_key).unwrap().as_slice());
    bos.write(base64.as_bytes()).unwrap();
    bos.write(name.as_bytes()).unwrap();
    Ok(bos.into_vec())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|x| format!("{:02X}", x))
        .collect::<Vec<_>>()
        .join("")
}

fn test() {
    let password: [u8; 70] = [
        0x35, 0x39, 0x32, 0x37, 0x38, 0x31, 0xe6, 0x3d, 0xd9, 0x59, 0x65, 0x1c, 0x21, 0x16, 0x00,
        0xf3, 0xb6, 0x56, 0x1d, 0x0b, 0x9d, 0x90, 0xaf, 0x09, 0xd0, 0xa4, 0xa4, 0x53, 0xee, 0x20,
        0x59, 0xa4, 0x80, 0xcc, 0x7c, 0x5a, 0x94, 0xd4, 0xd4, 0x89, 0x33, 0xf9, 0xff, 0xf5, 0xfe,
        0x43, 0x31, 0x7d, 0x52, 0xfa, 0x7b, 0xff, 0x8f, 0x8b, 0xc4, 0xf3, 0x48, 0x8b, 0x80, 0x07,
        0x33, 0x0f, 0xec, 0x7c, 0x7e, 0xdc, 0x91, 0xc2, 0x0e, 0x5d,
    ];
    let spake2_context = boring::curve25519::Spake2Context::new(
        boring::curve25519::Spake2Role::Alice,
        CLIENT_NAME,
        SERVER_NAME,
    )
    .unwrap();
    let mut outbound_msg = vec![0u8; 32];
    spake2_context
        .generate_message(outbound_msg.as_mut_slice(), 32, password.as_ref())
        .unwrap();
    println!("{:?}", outbound_msg.as_slice());
    println!("{}", hex::encode_upper(outbound_msg));
    let stdin = std::io::stdin();
    let line1 = stdin.lock().lines().next().unwrap().unwrap();
    let mut bob = hex::decode(line1).unwrap();
    let mut bob_key = vec![0u8; 64];
    spake2_context
        .process_message(bob_key.as_mut_slice(), 64, bob.as_mut_slice())
        .unwrap();
    println!("{}", hex::encode_upper(bob_key.clone()));

    let mut secret_key = [0u8; 16];
    hkdf::Hkdf::<sha2::Sha256>::new(None, bob_key.as_ref())
        .expand(
            "adb pairing_auth aes-128-gcm key".as_bytes(),
            &mut secret_key,
        )
        .unwrap();
    println!(
        "secret key: {:?}",
        boring::base64::encode_block(secret_key.as_slice())
    );

    let mut decrypt_iv: i64 = 0;
    let mut encrypt_iv: i64 = 0;

    let mut iv_bytes = bytebuffer::ByteBuffer::new();
    iv_bytes.resize(12);
    iv_bytes.set_endian(bytebuffer::Endian::LittleEndian);
    iv_bytes.write_i64(encrypt_iv);
    encrypt_iv += 1;

    let iv = iv_bytes.as_bytes();
    println!("iv: {:?}", boring::base64::encode_block(iv));

    let mut crypter = boring::symm::Crypter::new(
        boring::symm::Cipher::aes_128_gcm(),
        boring::symm::Mode::Encrypt,
        secret_key.as_ref(),
        Some(iv),
    )
    .unwrap();

    let mut peerinfo = bytebuffer::ByteBuffer::new();
    peerinfo.resize(MAX_PEER_INFO_SIZE as usize);
    peerinfo.set_endian(bytebuffer::Endian::BigEndian);
    peerinfo.write_string("kjsabkabskjnaxslzkbjhmjnkmlkasjbh");

    let mut encrypted = vec![0u8; peerinfo.len()];
    crypter
        .update(peerinfo.as_bytes(), encrypted.as_mut_slice())
        .unwrap();
    let fin = crypter.finalize(encrypted.as_mut_slice()).unwrap();

    let mut encryption_tag = vec![0u8; 16];
    crypter.get_tag(encryption_tag.as_mut_slice()).unwrap();
    println!("peerinfo: {:?}", hex::encode_upper(peerinfo.as_bytes()));
    println!("finalized write: {:?}", fin);
    encrypted.append(encryption_tag.as_mut());
    println!("encrypted: {:?}", hex::encode_upper(encrypted.as_slice()));
}

async fn pair(host: String, port: String, code: String) {
    // let host = "192.168.31.169".to_string();
    // let port = "45393".to_string();
    // let code = "312501".to_string();

    // Check cert file existance
    let cert_path = std::path::Path::new("cert.pem");
    let pkey_path = std::path::Path::new("pkey.pem");

    let x509: Option<boring::x509::X509>;
    let pkey: Option<boring::pkey::PKey<boring::pkey::Private>>;

    if !cert_path.exists() || !pkey_path.exists() {
        let (x509_raw, pkey_raw) = generate_cert().unwrap();
        x509 = Some(x509_raw.clone());
        pkey = Some(pkey_raw.clone());
        let mut cert_file = std::fs::File::create(cert_path).unwrap();
        let mut pkey_file = std::fs::File::create(pkey_path).unwrap();
        cert_file
            .write_all(x509_raw.to_pem().unwrap().as_slice())
            .unwrap();
        pkey_file
            .write_all(pkey_raw.private_key_to_pem_pkcs8().unwrap().as_slice())
            .unwrap();
    } else {
        // Load cert and pkey from file
        let cert_file = std::fs::File::open(cert_path).unwrap();
        let pkey_file = std::fs::File::open(pkey_path).unwrap();
        let x509_raw: Vec<u8> = cert_file.bytes().map(|x| x.unwrap()).collect();
        let x509_raw = x509_raw.as_slice();
        let pkey_raw: Vec<u8> = pkey_file.bytes().map(|x| x.unwrap()).collect();
        let pkey_raw = pkey_raw.as_slice();

        x509 = Some(boring::x509::X509::from_pem(x509_raw).unwrap());
        pkey = Some(boring::pkey::PKey::private_key_from_pem(pkey_raw).unwrap());
    }

    // x509.unwrap().public_key().unwrap().rsa()

    let domain = host.clone() + ":" + port.as_str();
    let method = boring::ssl::SslMethod::tls();
    let mut connector = boring::ssl::SslConnector::builder(method).unwrap();
    connector.set_verify(boring::ssl::SslVerifyMode::PEER);
    // The following two line is critical for ADB client auth, without them system_server will throw out "No peer certificate" error.
    connector
        .set_certificate(x509.clone().unwrap().as_ref())
        .unwrap();
    connector
        .set_private_key(pkey.clone().unwrap().as_ref())
        .unwrap();

    let mut config = connector.build().configure().unwrap();
    config.set_verify_callback(boring::ssl::SslVerifyMode::PEER, |_, _| true);
    let stream = tokio::net::TcpStream::connect(domain.as_str())
        .await
        .unwrap();
    let mut stream = tokio_boring::connect(config, host.as_str(), stream)
        .await
        .unwrap();
    // To ensure the connection is not stolen while we do the PAKE, append the exported key material from the
    // tls connection to the password.
    let mut exported_key_material = [0; 64];
    stream
        .ssl()
        .export_keying_material(&mut exported_key_material, EXPORTED_KEY_LABEL, None)
        .unwrap();
    println!("exported_key_material: {:?}", exported_key_material);

    let mut password = vec![0u8; code.as_bytes().len() + exported_key_material.len()];
    password[..code.as_bytes().len()].copy_from_slice(code.as_bytes());
    password[code.as_bytes().len()..].copy_from_slice(&exported_key_material);
    let spake2_context = boring::curve25519::Spake2Context::new(
        boring::curve25519::Spake2Role::Alice,
        CLIENT_NAME,
        SERVER_NAME,
    )
    .unwrap();
    let mut outbound_msg = vec![0u8; 32];
    spake2_context
        .generate_message(outbound_msg.as_mut_slice(), 32, password.as_ref())
        .unwrap();

    // Set header
    let mut header = bytebuffer::ByteBuffer::new();
    header.resize(6);
    header.set_endian(bytebuffer::Endian::BigEndian);
    // Write in data
    // Write version
    header.write_u8(1);
    // Write message type
    header.write_u8(0);
    // Write message length
    header.write_i32(outbound_msg.len() as i32);

    // Send data
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(outbound_msg.as_slice()).await.unwrap();

    // Read data
    stream.read_u8().await.unwrap();
    let msg_type = stream.read_u8().await.unwrap();
    let payload_length = stream.read_i32().await.unwrap();
    if msg_type != 0u8 {
        panic!("Message type miss match")
    }

    let mut payload_raw = vec![0u8; payload_length as usize];
    stream.read_exact(payload_raw.as_mut_slice()).await.unwrap();

    let mut bob_key = vec![0u8; 64];
    spake2_context
        .process_message(bob_key.as_mut_slice(), 64, payload_raw.as_mut_slice())
        .unwrap();

    // Has checked the hkdf generation process is correct
    // TODO: Check if the bob key is the same
    println!(
        "bob key: {:?}",
        boring::base64::encode_block(bob_key.as_slice())
    );
    let mut secret_key = [0u8; 16];
    hkdf::Hkdf::<sha2::Sha256>::new(None, bob_key.as_ref())
        .expand(
            "adb pairing_auth aes-128-gcm key".as_bytes(),
            &mut secret_key,
        )
        .unwrap();
    println!(
        "secret key: {:?}",
        boring::base64::encode_block(secret_key.as_slice())
    );

    let mut decrypt_iv: i64 = 0;
    let mut encrypt_iv: i64 = 0;

    let mut iv_bytes = bytebuffer::ByteBuffer::new();
    iv_bytes.resize(12);
    iv_bytes.set_endian(bytebuffer::Endian::LittleEndian);
    iv_bytes.write_i64(encrypt_iv);
    encrypt_iv += 1;

    let iv = iv_bytes.as_bytes();

    let mut crypter = boring::symm::Crypter::new(
        boring::symm::Cipher::aes_128_gcm(),
        boring::symm::Mode::Encrypt,
        secret_key.as_ref(),
        Some(iv),
    )
    .unwrap();

    let mut peerinfo = bytebuffer::ByteBuffer::new();
    peerinfo.resize(MAX_PEER_INFO_SIZE as usize);
    peerinfo.set_endian(bytebuffer::Endian::BigEndian);

    peerinfo.write_u8(0);
    peerinfo
        .write(
            encode_rsa_publickey_with_name(x509.unwrap().public_key().unwrap().rsa().unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();

    let mut encrypted = vec![0u8; peerinfo.as_bytes().len()];
    crypter
        .update(peerinfo.as_bytes(), encrypted.as_mut_slice())
        .unwrap();
    let fin = crypter.finalize(encrypted.as_mut_slice()).unwrap();
    if fin != 0 {
        panic!("Finalize error");
    }

    let mut encryption_tag = vec![0u8; 16];
    crypter.get_tag(encryption_tag.as_mut_slice()).unwrap();
    encrypted.append(encryption_tag.as_mut());
    // Set header    // Write version
    let mut header = bytebuffer::ByteBuffer::new();
    header.resize(6);
    header.set_endian(bytebuffer::Endian::BigEndian);
    // Write in data
    header.write_u8(1);
    // Write message type
    header.write_u8(1);
    // Write message length
    header.write_i32(encrypted.len() as i32);

    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(encrypted.as_slice()).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(100)).await;
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Pair {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: i32,
        #[arg(long)]
        code: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(command) => {
            match command {
                Commands::Pair { host, port, code } =>{
                    pair(host, port.to_string(), code).await
                }
            }
        }
        None => println!("Please pass a command"),
    }
    //pair().await;
    // protocol::stls_connect().await;
}
