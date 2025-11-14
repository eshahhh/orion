"""Issue server/client cert signed by Root CA."""
import os
import sys
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def load_ca(ca_key_path="certs/ca_key.pem", ca_cert_path="certs/ca_cert.pem"):

    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_private_key, ca_cert


def generate_certificate(
    common_name,
    cert_type="server",
    ca_key_path="certs/ca_key.pem",
    ca_cert_path="certs/ca_cert.pem",
    cert_key_path=None,
    cert_path=None,
    organization="OrionLink",
    country="US",
    validity_days=365
):

    if cert_key_path is None:
        cert_key_path = f"certs/{common_name}_key.pem"
    if cert_path is None:
        cert_path = f"certs/{common_name}_cert.pem"
    
    os.makedirs(os.path.dirname(cert_key_path), exist_ok=True)
    
    ca_private_key, ca_cert = load_ca(ca_key_path, ca_cert_path)
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
    )
    
    if cert_type == "server":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        )
    else:  # client
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
    
    cert = builder.sign(ca_private_key, hashes.SHA256())
    
    with open(cert_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"{cert_type.capitalize()} certificate private key saved to: {cert_key_path}")
    print(f"{cert_type.capitalize()} certificate saved to: {cert_path}")
    print(f"Valid for {validity_days} days")
    print(f"Subject: {common_name}")
    print(f"SAN: DNSName({common_name})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python gen_cert.py <common_name> [cert_type]")
        print("  common_name: e.g., 'server.orionlink.local' or 'client1'")
        print("  cert_type: 'server' or 'client' (default: server)")
        sys.exit(1)
    
    common_name = sys.argv[1]
    cert_type = sys.argv[2] if len(sys.argv) > 2 else "server"
    
    if cert_type not in ["server", "client"]:
        print("Error: cert_type must be 'server' or 'client'")
        sys.exit(1)
    
    generate_certificate(common_name, cert_type)
