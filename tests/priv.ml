open X509

let pk_equal a b =
  String.equal
    Digestif.SHA256.(to_raw_string (digest_string (Private_key.encode_der a)))
    Digestif.SHA256.(to_raw_string (digest_string (Private_key.encode_der b)))

let generate_rsa () =
  let seed = "Test1234" in
  let pk = Private_key.generate ~seed `RSA in
  let pk' = Result.get_ok (Private_key.of_string `RSA seed) in
  let pk'' = Result.get_ok (Private_key.of_string ~seed_or_data:`Seed `RSA seed) in
  Alcotest.(check bool "generate and of_string" true (pk_equal pk pk'));
  Alcotest.(check bool "generate and of_string ~seed" true (pk_equal pk pk''));
  match Private_key.of_string ~seed_or_data:`Data `RSA seed with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "expected failure (of_string `Data `RSA)"

let b64_dec s = Base64.decode_exn s

let test_ec (key_type, data) () =
  let pk = Result.get_ok (Private_key.of_octets (b64_dec data) key_type) in
  let pk' = Result.get_ok (Private_key.of_string key_type data) in
  let pk'' = Result.get_ok (Private_key.of_string ~seed_or_data:`Data key_type data) in
  Alcotest.(check bool "generate and of_string" true (pk_equal pk pk'));
  Alcotest.(check bool "generate and of_string ~data" true (pk_equal pk pk''));
  match Private_key.of_string ~seed_or_data:`Seed key_type data with
  | Error _ -> Alcotest.fail "expected ok (of_string `Seed)"
  | Ok pk''' -> Alcotest.(check bool "generate and of_String ~seed" false (pk_equal pk pk'''))


let _compile_test =
  (* make sure Dsa module can be used directly *)
  let _f (pk : Private_key.t) =
    match pk with
    | `ECDSA Ecdsa k ->
      let (module C) = k.curve in
      let key = k.priv in
      C.Dsa.sign ~key "foo"
    | _ -> "", "";
  in
  let _f (pk : Public_key.t) =
  match pk with
  | `ECDSA Ecdsa k ->
    let (module C) = k.curve in
    let key = k.pub in
    C.Dsa.verify ~key ("foo", "bar") "xyz"
  | _ -> true; in
 ()

let p256 = Dsa_curves.register "p256" Dsa_curves.OIDs.secp256r1 (module Mirage_crypto_ec.P256.Dsa)
let p384 = Dsa_curves.register "p384" Dsa_curves.OIDs.secp384r1 (module Mirage_crypto_ec.P384.Dsa)
let p521 = Dsa_curves.register "p521" Dsa_curves.OIDs.secp521r1 (module Mirage_crypto_ec.P521.Dsa)


let ec_data = [
  `ED25519, "W0p4c4tBHtSaTj4zij4oARCjhFbIi8voYg+65bl7wLU=" ;
  (`ECDSA p256), "arvDmHpdTdzbc0uo+KCXoArmrmAs2GAvfk14D8gi6gM=" ;
  (`ECDSA p384), "UEZz/xVx2f3s7W8/cFy/w38LkjAq0xfMYJiXamdwgW9zwSK18+vrhKzgE23sFnyq" ;
  (`ECDSA p521), "AVb4DIpMO5hzyfX1n4qi4xtj/JBDCTCwyOLasKnnVS6FHW2hEZbGwd1c2J4rwpNKZqTKNsKu3dVJAmlp3EFhqv5T" ;
  (* `P256K1, "r7c6teVRVw1OpWUM/xOx8D35Uiu9N9G2kEE54tPJRKw=" ;
  `BRAINPOOLP256R1, "EwzWx38kl147Bi6yKer3sk8f1jMWOeCdgpd69QePBy0=" ;
  `BRAINPOOLP384R1, "HComUhVG3jAHytfnHeIaoxV3ZMj5zHcLua8Z9pREnGNNlxtkgifHVXMRCa0wgWOh" ;
  `BRAINPOOLP512R1, "CBRJFGHzV5TFOcXZvSrEXzfZp92sPUJi7Fb/Tgpv/QRdV72UYV8lUJ5WUv0uofVpumS3yA/2LrgJtanyN81cnw==" ; *)
]

let tests =
  ("Generate RSA", `Quick, generate_rsa) ::
  List.map (fun d -> Key_type.to_string (fst d), `Quick, test_ec d) ec_data
