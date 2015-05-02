0.3.1 (2015-05-02):
* PKCS8 private key info support (only unencrypted keys so far)

0.3.0 (2015-03-19):
* more detailed error messages (type certificate_failure modified)
* no longer Printf.printf debug messages
* error reporting: `Ok of certificate option | `Fail of certificate_failure
* fingerprint verification can work with None as host (useful for client authentication where host is not known upfront)
* API reshape: X509 is the only public module, X509.t is the abstract certificate

0.2.1 (2014-12-21):
* server_fingerprint authenticator which validates the server certificate based on a hash algorithm and (server_name * fingerprint) list instead of a set of trust anchors
* whitelist CAcert certificates (which do not include mandatory X.509v3 KeyUsage extension)

0.2.0 (2014-10-30):
* expose Certificate.cert_hostnames, wildcard_matches
* Certificate.verify_chain_of_trust and X509.authenticate both return now
  [ `Ok of certificate | `Fail of certificate_failure ], where [certificate] is the trust anchor

0.1.0 (2014-07-08):
* initial beta release
