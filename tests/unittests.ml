open OUnit2

let suite =
  "All" >::: [
    "X509" >::: X509tests.x509_tests ;
  ]
