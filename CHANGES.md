(trunk):
* more detailed error messages (type certificate_failure modified)
* no longer Printf.printf debug messages
* API change: X509.authenticate receives a certificate list and returns an optional trust anchor [ `Ok of certificate option | `Fail of error ]
* API change: cert_pubkey is now available, supports_keytype, supports_usage, supports_extended_usage are now there
* library is now packed

0.2.1 (2014-12-21):
* server_fingerprint authenticator which validates the server certificate based on a hash algorithm and (server_name * fingerprint) list instead of a set of trust anchors
* whitelist CAcert certificates (which do not include mandatory X.509v3 KeyUsage extension)

0.2.0 (2014-10-30):
* expose Certificate.cert_hostnames, wildcard_matches
* Certificate.verify_chain_of_trust and X509.authenticate both return now
  [ `Ok of certificate | `Fail of certificate_failure ], where [certificate] is the trust anchor

0.1.0 (2014-07-08):
* initial beta release
