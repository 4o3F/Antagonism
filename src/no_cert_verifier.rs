use std::time::SystemTime;

use tokio_rustls::rustls::{Certificate, Error, ServerName};
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};

pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item=&[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        //println!("Server Name: {:?}, Entity: {:?}", _server_name, String::from_utf8(_end_entity.0.to_owned()));
        Ok(ServerCertVerified::assertion())
    }
}