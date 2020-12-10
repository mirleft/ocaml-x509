

let test_raw_private_key () =
  let pk = Mirage_crypto_pk.Rsa.generate ~bits:1024 () in
  let safebag = X509.Pkcs12.SafeBag.KeyBag pk, [] in
  let safecontents = [safebag] in
  let autheticated_safe = [safecontents] in
  let pfx = autheticated_safe in
  let codec = Asn.codec Asn.ber X509.Pkcs12.Asn.pfx in
  let pfx_ber = Asn.encode codec pfx in
  let result = pfx_ber in
  (* Hex.(of_cstruct result |> hexdump ~print_chars:false); *)
  (* Hex.(to_string @@ of_cstruct result |> Base64.encode_exn |> print_endline); *)
  Cstruct.hexdump result;
  Cstruct.to_string result |> Base64.encode_exn |> print_endline;
  (* let out = open_out_bin "/tmp/1.p12" in
   * output_string out (Cstruct.to_string result);
   * close_out out; *)
  assert (1 = 1)


let test_cert_and_raw_key () =
  let pk = X509tests.priv in
  let cert = X509tests.cacert in
  let cert_hash = X509.Certificate.fingerprint `SHA1 cert in
  let safebag_key = X509.Pkcs12.(SafeBag.KeyBag pk, [
      Attribute.LocalKeyId cert_hash
    ]) in
  let safebag_cert = X509.Pkcs12.(SafeBag.CertBag cert, [
      Attribute.LocalKeyId cert_hash
    ]) in
  let safecontents = [safebag_key; safebag_cert] in
  let autheticated_safe = [safecontents] in
  let pfx = autheticated_safe in
  let codec = Asn.codec Asn.ber X509.Pkcs12.Asn.pfx in
  let pfx_ber = Asn.encode codec pfx in
  let result = pfx_ber in
  (* Hex.(of_cstruct result |> hexdump ~print_chars:false); *)
  (* Hex.(to_string @@ of_cstruct result |> Base64.encode_exn |> print_endline); *)
  Cstruct.hexdump result;
  Cstruct.to_string result |> Base64.encode_exn |> print_endline;
  let out = open_out_bin "/tmp/1.p12" in
  output_string out (Cstruct.to_string result);
  close_out out;
  assert (1 = 2)


let tests = [
  "Test raw private_key pack", `Quick, test_raw_private_key ;
  "Test cert and raw private_key pack", `Quick, test_cert_and_raw_key ;
]
