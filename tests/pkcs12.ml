open X509

let mmap file =
  let ic = open_in file in
  let ln = in_channel_length ic in
  let rs = Bytes.create ln in
  really_input ic rs 0 ln;
  close_in ic;
  Bytes.unsafe_to_string rs

let data file = mmap ("./pkcs12/" ^ file)

let cert = match Certificate.decode_pem (data "certificate.pem") with
  | Ok c -> c
  | Error _ -> assert false

let key = match Private_key.decode_pem (data "key.pem") with
  | Ok k -> k
  | Error _ -> assert false

let pass = "1234"

let cert_and_key xs =
  match xs with
  | [ `Certificate c ; `Decrypted_private_key k ] ->
    Alcotest.(check bool __LOC__ true (c = cert && k = key))
  | _ -> Alcotest.fail "expected certificate and key"

let openssl1 () =
  match PKCS12.decode_der (data "ossl.p12") with
  | Error `Msg m -> Alcotest.fail ("failed to decode ossl.p12: " ^ m)
  | Ok data ->
    match PKCS12.verify pass data with
    | Ok xs -> cert_and_key xs
    | Error `Msg m -> Alcotest.fail ("failed to verify ossl.p12: " ^ m)

let openssl2 () =
  match PKCS12.decode_der (data "ossl_aes.p12") with
  | Error _ -> Alcotest.fail "failed to decode ossl_aes.p12"
  | Ok data ->
    match PKCS12.verify pass data with
    | Ok xs -> cert_and_key xs
    | Error _ -> Alcotest.fail "failed to verify ossl_aes.p12"

let ours () =
  match PKCS12.decode_der (data "ours.p12") with
  | Error _ -> Alcotest.fail "failed to decode ours.p12"
  | Ok data ->
    match PKCS12.verify pass data with
    | Ok xs -> cert_and_key xs
    | Error _ -> Alcotest.fail "failed to verify ours.p12"

let roundtrip () =
  let p12 = PKCS12.create pass [ cert ] key in
  match PKCS12.verify pass p12 with
  | Ok xs -> cert_and_key xs
  | Error _ -> Alcotest.fail "failed roundtrip"

let tests = [
  "OpenSSL basic", `Quick, openssl1 ;
  "OpenSSL AES 256", `Quick, openssl2 ;
  "OCaml-X509 AES 256", `Quick, ours ;
  "OCaml-X509 create and verify", `Quick, roundtrip ;
]
