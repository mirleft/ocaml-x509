open X509

let of_ic ic =
  let ln = in_channel_length ic in
  let rs = Bytes.create ln in
  really_input ic rs 0 ln;
  Bytes.unsafe_to_string rs

let with_loaded_files file ~f =
  let pre = "./crl/" in
  let fullpath1 = pre ^ file ^ ".pem"
  and fullpath2 = pre ^ file ^ ".crl"
  in
  let fd1 = open_in fullpath1
  and fd2 = open_in fullpath2
  in
  let buf1 = of_ic fd1
  and buf2 = of_ic fd2
  in
  try let r = f buf1 buf2 in close_in fd1 ; close_in fd2 ;
    match r with
    | Ok x -> x
    | Error (`Msg e) -> Alcotest.failf "decoding error %s" e
  with e -> close_in fd1 ; close_in fd2 ;
    Alcotest.failf "exception %s" (Printexc.to_string e)

let allowed_hashes = [ `SHA1 ; `SHA256 ; `SHA384 ; `SHA512 ]

let one f () =
  with_loaded_files f ~f:(fun cert crl ->
      let ( let* ) = Result.bind in
      let* cert = Certificate.decode_pem cert in
      let pubkey = Certificate.public_key cert in
      let* crl = CRL.decode_der crl in
      Result.map_error
        (fun e -> `Msg (Fmt.to_to_string Validation.pp_signature_error e))
        (CRL.validate crl ~allowed_hashes pubkey))

let crl_tests = [
  "CRL 1 is good", `Quick, one "1" ;
  "CRL 2 is good", `Quick, one "2" ;
  "CRL 3 is good", `Quick, one "3" ;
  "CRL 4 is good", `Quick, one "4" ;
  "CRL 5 is good", `Quick, one "5" ;
  "CRL 6 is good", `Quick, one "6" ;
  "CRL 7 is good", `Quick, one "7" ;
  "CRL 8 is good", `Quick, one "8" ;
  "CRL 9 is good", `Quick, one "9" ;
  "CRL 10 is good", `Quick, one "10" ;
  "CRL 11 is good", `Quick, one "11" ;
  "CRL 12 is good", `Quick, one "12" ;
  "CRL 13 is good", `Quick, one "13" ;
  "CRL 14 is good", `Quick, one "14" ;
  "CRL 15 is good", `Quick, one "15" ;
  "CRL 16 is good", `Quick, one "16" ;
  "CRL 17 is good", `Quick, one "17" ;
  "CRL 18 is good", `Quick, one "18" ;
  "CRL 19 is good", `Quick, one "19" ;
  "CRL 20 is good", `Quick, one "20" ;
  "CRL 21 is good", `Quick, one "21" ;
]
