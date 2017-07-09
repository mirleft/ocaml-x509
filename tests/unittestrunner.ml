open OUnit2

let () =
  Nocrypto_entropy_unix.initialize ();
  run_test_tt_main Unittests.suite
