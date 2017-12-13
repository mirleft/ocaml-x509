open OUnit2

let suite =
  "All" >::: [
    "Revoke" >::: Revoke.revoke_tests ;
    "X509" >::: X509tests.x509_tests ;
    "CRL" >::: Crltests.crl_tests ;
  ]
