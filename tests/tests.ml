let suites =
  X509tests.x509_tests @ [
    "Regression", Regression.regression_tests ;
    "Host names", Regression.hostname_tests ;
    "Revoke", Revoke.revoke_tests ;
    "CRL", Crltests.crl_tests ;
    "PKCS12", Pkcs12.tests ;
    "OCSP", Ocsp.tests ;
    "Private Key", Priv.tests ;
  ]


let () =
  Printexc.record_backtrace true;
  Mirage_crypto_rng_unix.use_default ();
  Alcotest.run "X509 tests" suites
