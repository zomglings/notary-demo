use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use std::fs;
use std::path::PathBuf;
use std::io::Write;

pub fn generate_certificates(domain: &str, aliases: &[String], outdir: &PathBuf, prefix: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Create output directory if it doesn't exist
    match fs::create_dir_all(outdir) {
        Ok(_) => {},
        Err(e) => {
            return Err(format!("Failed to create output directory: {}", e).into());
        }
    }

    // Prepare certificate parameters
    let mut params = CertificateParams::default();
    
    // Set the primary domain as Common Name
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, domain);
    params.distinguished_name = distinguished_name;
    
    // Add the primary domain and aliases as Subject Alternative Names
    params.subject_alt_names.push(SanType::DnsName(domain.to_string()));
    
    for alias in aliases {
        params.subject_alt_names.push(SanType::DnsName(alias.clone()));
    }
    
    // Generate the certificate
    let cert = match rcgen::Certificate::from_params(params) {
        Ok(cert) => cert,
        Err(e) => {
            return Err(format!("Failed to generate certificate: {}", e).into());
        }
    };
    
    // Get the certificate and private key in PEM format
    let cert_pem = match cert.serialize_pem() {
        Ok(pem) => pem,
        Err(e) => {
            return Err(format!("Failed to serialize certificate: {}", e).into());
        }
    };
    
    let key_pem = cert.serialize_private_key_pem();
    
    // Create filenames with prefix
    let filename_prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{}.", prefix)
    };
    
    // Write certificate to file
    let cert_path = outdir.join(format!("{}cert.pem", filename_prefix));
    match std::fs::File::create(&cert_path) {
        Ok(mut file) => {
            match file.write_all(cert_pem.as_bytes()) {
                Ok(_) => {},
                Err(e) => {
                    return Err(format!("Failed to write certificate to file: {}", e).into());
                }
            }
        },
        Err(e) => {
            return Err(format!("Failed to create certificate file: {}", e).into());
        }
    }
    
    // Write private key to file
    let key_path = outdir.join(format!("{}key.pem", filename_prefix));
    match std::fs::File::create(&key_path) {
        Ok(mut file) => {
            match file.write_all(key_pem.as_bytes()) {
                Ok(_) => {},
                Err(e) => {
                    return Err(format!("Failed to write private key to file: {}", e).into());
                }
            }
        },
        Err(e) => {
            return Err(format!("Failed to create private key file: {}", e).into());
        }
    }
    
    Ok(outdir.to_path_buf())
} 