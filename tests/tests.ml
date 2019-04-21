
let suites = [
  "Revoke", Revoke.revoke_tests ;
  "X509", X509tests.x509_tests ;
  "CRL", Crltests.crl_tests ;
]

let () =
  Nocrypto_entropy_unix.initialize ();
  Alcotest.run "X509 tests" suites
