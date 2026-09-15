# Test cases for X.509 certificate checking
# Copyright (c) 2019, The Linux Foundation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import datetime
import os
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    cryptography_imported = True
except ImportError:
    cryptography_imported = False

from utils import HwsimSkip
import hostapd
from test_ap_eap import check_domain_suffix_match, check_altsubject_match_support, check_domain_match

def check_cert_check_support():
    if not cryptography_imported:
        raise HwsimSkip("cryptography python module not available")

def start_hapd(apdev, server_cert="auth_serv/server.pem"):
    params = {"ssid": "cert-check", "wpa": "2", "wpa_key_mgmt": "WPA-EAP",
              "rsn_pairwise": "CCMP", "ieee8021x": "1",
              "eap_server": "1", "eap_user_file": "auth_serv/eap_user.conf",
              "ca_cert": "auth_serv/ca.pem",
              "server_cert": server_cert,
              "private_key": "auth_serv/server.key",
              "dh_file": "auth_serv/dh.conf"}
    hapd = hostapd.add_ap(apdev, params)
    return hapd

def load_certs():
    with open("auth_serv/ca.pem", "rb") as f:
        cacert = x509.load_pem_x509_certificate(f.read())

    with open("auth_serv/ca-key.pem", "rb") as f:
        cakey = serialization.load_pem_private_key(f.read(), None)

    with open("auth_serv/server.pem", "rb") as f:
        servercert = x509.load_pem_x509_certificate(f.read())

    return cacert, cakey, servercert

def authority_key_identifier(cacert):
    # Mimic OpenSSL's "keyid:always": use the issuer's subjectKeyIdentifier
    # when present, otherwise derive the key id from its public key.
    try:
        ski = cacert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier).value
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key())

def add_server_cert_extensions(builder, pubkey, cacert):
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(pubkey), critical=False)
    builder = builder.add_extension(authority_key_identifier(cacert),
                                    critical=False)
    return builder

def start_cert(servercert, cacert, cn='server.w1.fi'):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(12345)
    builder = builder.not_valid_before(now - datetime.timedelta(seconds=10))
    builder = builder.not_valid_after(now + datetime.timedelta(seconds=1000))
    builder = builder.public_key(servercert.public_key())
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
    return add_server_cert_extensions(builder, servercert.public_key(), cacert)

def sign_cert(cert, cert_file, cakey, cacert):
    cert = cert.issuer_name(cacert.subject)
    signed = cert.sign(private_key=cakey, algorithm=hashes.SHA256())
    with open(cert_file, 'wb') as f:
        f.write(signed.public_bytes(serialization.Encoding.PEM))

def check_connect(dev, fail=False, wait_error=None, **kwargs):
    dev.connect("cert-check", key_mgmt="WPA-EAP", eap="TTLS",
                identity="pap user", anonymous_identity="ttls",
                password="password",
                ca_cert="auth_serv/ca.pem", phase2="auth=PAP",
                scan_freq="2412", wait_connect=False, **kwargs)
    ev = dev.wait_event(["CTRL-EVENT-EAP-STARTED"], timeout=10)
    if ev is None:
        raise Exception("EAP not started")
    if fail:
        if wait_error:
            ev = dev.wait_event([wait_error], timeout=5)
            if ev is None:
                raise Exception("Specific error not reported")
        ev = dev.wait_event(["CTRL-EVENT-EAP-FAILURE"], timeout=5)
        if ev is None:
            raise Exception("EAP failure not reported")
    else:
        dev.wait_connected()
    dev.request("REMOVE_NETWORK all")
    dev.request("ABORT_SCAN")
    dev.wait_disconnected()
    dev.dump_monitor()

def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def der_tlv(tag, value):
    return bytes([tag]) + der_len(len(value)) + value

def der_integer(n):
    content = n.to_bytes(max((n.bit_length() + 7) // 8, 1), 'big')
    if content[0] & 0x80:
        content = b'\x00' + content
    return der_tlv(0x02, content)

# AlgorithmIdentifier for sha256WithRSAEncryption (1.2.840.113549.1.1.11).
SHA256_RSA_ALG_ID = bytes.fromhex('300d06092a864886f70d01010b0500')

def sign_v1_cert(cert_file, cn='server.w1.fi', key_file="auth_serv/server.key",
                 ca_cert="auth_serv/ca.pem", ca_key="auth_serv/ca-key.pem"):
    # cryptography's CertificateBuilder always emits a v3 certificate and the
    # "openssl x509 -req" is version-dependent, so do it here manually
    with open(key_file, "rb") as f:
        pkey = serialization.load_pem_private_key(f.read(), None)
    with open(ca_cert, "rb") as f:
        cacert = x509.load_pem_x509_certificate(f.read())
    with open(ca_key, "rb") as f:
        cakey = serialization.load_pem_private_key(f.read(), None)
    if not isinstance(cakey, rsa.RSAPrivateKey):
        raise Exception("sign_v1_cert() only supports an RSA ca_key")

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(seconds=10)
    not_after = now + datetime.timedelta(seconds=1000)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    pubkey_der = pkey.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    validity = der_tlv(0x30,
        der_tlv(0x17, not_before.strftime('%y%m%d%H%M%SZ').encode()) +
        der_tlv(0x17, not_after.strftime('%y%m%d%H%M%SZ').encode()))
    tbs = der_tlv(0x30, der_integer(12345) + SHA256_RSA_ALG_ID +
                  cacert.subject.public_bytes() + validity +
                  subject.public_bytes() + pubkey_der)
    signature = cakey.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    cert_der = der_tlv(0x30, tbs + SHA256_RSA_ALG_ID +
                       der_tlv(0x03, b'\x00' + signature))

    signed = x509.load_der_x509_certificate(cert_der)
    if signed.version != x509.Version.v1:
        raise Exception("sign_v1_cert() did not produce an X.509v1 certificate")
    with open(cert_file, "wb") as f:
        f.write(signed.public_bytes(serialization.Encoding.PEM))

def test_cert_check_basic(dev, apdev, params):
    """Certificate check with a plain X.509v1 server certificate (no extensions)"""
    check_cert_check_support()
    cert_file = os.path.join(params['logdir'], "cert_check_basic.pem")
    sign_v1_cert(cert_file)
    hapd = start_hapd(apdev[0], server_cert=cert_file)
    check_connect(dev[0])

def test_cert_check_v3(dev, apdev, params):
    """Basic test with generated X.509v3 server certificate"""
    check_cert_check_support()
    cert_file = os.path.join(params['logdir'], "cert_check_v3.pem")
    cacert, cakey, servercert = load_certs()

    cert = start_cert(servercert, cacert)
    sign_cert(cert, cert_file, cakey, cacert)
    hapd = start_hapd(apdev[0], server_cert=cert_file)
    check_connect(dev[0])

def test_cert_check_dnsname(dev, apdev, params):
    """Certificate check with multiple dNSName values"""
    check_cert_check_support()
    check_domain_suffix_match(dev[0])
    check_domain_match(dev[0])
    cert_file = os.path.join(params['logdir'], "cert_check_dnsname.pem")
    cacert, cakey, servercert = load_certs()

    cert = start_cert(servercert, cacert, cn="server")
    dns = ["one.example.com", "two.example.com", "three.example.com"]
    cert = cert.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]),
        critical=False)
    sign_cert(cert, cert_file, cakey, cacert)
    hapd = start_hapd(apdev[0], server_cert=cert_file)
    check_connect(dev[0])

    tests = ["two.example.com",
             "one.example.com",
             "tWo.Example.com",
             "three.example.com",
             "no.match.example.com;two.example.com;no.match.example.org",
             "no.match.example.com;example.com;no.match.example.org",
             "no.match.example.com;no.match.example.org;example.com",
             "example.com",
             "com"]
    for match in tests:
        check_connect(dev[0], domain_suffix_match=match)

    tests = ["four.example.com",
             "foo.one.example.com",
             "no.match.example.org;no.match.example.com",
             "xample.com"]
    for match in tests:
        check_connect(dev[0], fail=True,
                      wait_error="CTRL-EVENT-EAP-TLS-CERT-ERROR",
                      domain_suffix_match=match)

    tests = ["one.example.com",
             "two.example.com",
             "three.example.com",
             "no.match.example.com;two.example.com;no.match.example.org",
             "tWo.Example.Com"]
    for match in tests:
        check_connect(dev[0], domain_match=match)

    tests = ["four.example.com",
             "foo.one.example.com",
             "example.com",
             "xample.com",
             "no.match.example.org;no.match.example.com",
             "ne.example.com"]
    for match in tests:
        check_connect(dev[0], fail=True,
                      wait_error="CTRL-EVENT-EAP-TLS-CERT-ERROR",
                      domain_match=match)

def test_cert_check_dnsname_wildcard(dev, apdev, params):
    """Certificate check with multiple dNSName wildcard values"""
    check_cert_check_support()
    check_domain_suffix_match(dev[0])
    check_domain_match(dev[0])
    cert_file = os.path.join(params['logdir'], "cert_check_dnsname.pem")
    cacert, cakey, servercert = load_certs()

    cert = start_cert(servercert, cacert, cn="server")
    dns = ["*.one.example.com", "two.example.com", "*.three.example.com"]
    cert = cert.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]),
        critical=False)
    sign_cert(cert, cert_file, cakey, cacert)
    hapd = start_hapd(apdev[0], server_cert=cert_file)
    check_connect(dev[0])

    tests = ["two.example.com",
             "one.example.com",
             "tWo.Example.com",
             "three.example.com",
             "no.match.example.com;two.example.com;no.match.example.org",
             "no.match.example.com;example.com;no.match.example.org",
             "no.match.example.com;no.match.example.org;example.com",
             "example.com",
             "com"]
    for match in tests:
        check_connect(dev[0], domain_suffix_match=match)

    tests = ["four.example.com",
             "foo.one.example.com",
             "no.match.example.org;no.match.example.com",
             "xample.com"]
    for match in tests:
        check_connect(dev[0], fail=True,
                      wait_error="CTRL-EVENT-EAP-TLS-CERT-ERROR",
                      domain_suffix_match=match)

    tests = ["*.one.example.com",
             "two.example.com",
             "*.three.example.com",
             "no.match.example.com;two.example.com;no.match.example.org",
             "tWo.Example.Com"]
    for match in tests:
        check_connect(dev[0], domain_match=match)

    tests = ["four.example.com",
             "foo.one.example.com",
             "example.com",
             "xample.com",
             "no.match.example.org;no.match.example.com",
             "one.example.com"]
    for match in tests:
        check_connect(dev[0], fail=True,
                      wait_error="CTRL-EVENT-EAP-TLS-CERT-ERROR",
                      domain_match=match)

def test_cert_check_dnsname_alt(dev, apdev, params):
    """Certificate check with multiple dNSName values using altsubject_match"""
    check_cert_check_support()
    check_altsubject_match_support(dev[0])
    cert_file = os.path.join(params['logdir'], "cert_check_dnsname_alt.pem")
    cacert, cakey, servercert = load_certs()

    cert = start_cert(servercert, cacert, cn="server")
    dns = ["*.one.example.com", "two.example.com", "*.three.example.com"]
    cert = cert.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]),
        critical=False)
    sign_cert(cert, cert_file, cakey, cacert)
    hapd = start_hapd(apdev[0], server_cert=cert_file)

    tests = ["DNS:*.one.example.com",
             "DNS:two.example.com",
             "DNS:*.three.example.com",
             "DNS:*.three.example.com;DNS:two.example.com;DNS:*.one.example.com",
             "DNS:foo.example.org;DNS:two.example.com;DNS:bar.example.org"]
    for alt in tests:
        check_connect(dev[0], altsubject_match=alt)

    tests = ["DNS:one.example.com",
             "DNS:four.example.com;DNS:five.example.com"]
    for alt in tests:
        check_connect(dev[0], fail=True,
                      wait_error="CTRL-EVENT-EAP-TLS-CERT-ERROR",
                      altsubject_match=alt)

def test_cert_check_dnsname_cn(dev, apdev, params):
    """Certificate check with dNSName in CN"""
    check_cert_check_support()
    check_domain_suffix_match(dev[0])
    check_domain_match(dev[0])
    cert_file = os.path.join(params['logdir'], "cert_check_dnsname_cn.pem")
    cacert, cakey, servercert = load_certs()

    cert = start_cert(servercert, cacert, cn="server.example.com")
    sign_cert(cert, cert_file, cakey, cacert)
    hapd = start_hapd(apdev[0], server_cert=cert_file)
    check_connect(dev[0])

    tests = ["server.example.com",
             "example.com",
             "eXample.Com",
             "no.match.example.com;example.com;no.match.example.org",
             "no.match.example.com;server.example.com;no.match.example.org",
             "com"]
    for match in tests:
        check_connect(dev[0], domain_suffix_match=match)

    tests = ["aaa.example.com",
             "foo.server.example.com",
             "no.match.example.org;no.match.example.com",
             "xample.com"]
    for match in tests:
        check_connect(dev[0], fail=True,
                      wait_error="CTRL-EVENT-EAP-TLS-CERT-ERROR",
                      domain_suffix_match=match)

    tests = ["server.example.com",
             "no.match.example.com;server.example.com;no.match.example.org",
             "sErver.Example.Com"]
    for match in tests:
        check_connect(dev[0], domain_match=match)

    tests = ["aaa.example.com",
             "foo.server.example.com",
             "example.com",
             "no.match.example.org;no.match.example.com",
             "xample.com"]
    for match in tests:
        check_connect(dev[0], fail=True,
                      wait_error="CTRL-EVENT-EAP-TLS-CERT-ERROR",
                      domain_match=match)
