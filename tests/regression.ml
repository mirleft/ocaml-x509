open X509

let mmap file =
  let ic = open_in file in
  let ln = in_channel_length ic in
  let rs = Bytes.create ln in
  really_input ic rs 0 ln;
  close_in ic;
  Bytes.unsafe_to_string rs

let regression file =
  mmap ("./regression/" ^ file ^ ".pem")

let read_cert file =
  match Certificate.decode_pem (regression file) with
  | Ok cert -> cert
  | Error (`Msg m) -> Alcotest.failf "certificate %s decoding error %s" file m

let jc = read_cert "jabber.ccc.de"
let cacert = read_cert "cacert"

let time () = None

let host str = Some (Domain_name.host_exn (Domain_name.of_string_exn str))

let test_jc_jc () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.ccc.de") ~time ~anchors:[jc] [jc] with
  | Error `InvalidChain -> ()
  | Error e -> Alcotest.failf "something went wrong with jc_jc (expected invalid_chain, got %a"
                 Validation.pp_validation_error e
  | Ok _ -> Alcotest.fail "chain validated when it shouldn't"

let test_jc_ca_fail () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.ccc.de") ~time ~anchors:[cacert] [jc ; cacert] with
  | Error `InvalidChain -> ()
  | _ -> Alcotest.fail "something went wrong with jc_ca"

let test_jc_ca_all_hashes () =
  match Validation.verify_chain_of_trust ~allowed_hashes:[`SHA1] ~host:(host "jabber.ccc.de") ~time ~anchors:[cacert] [jc ; cacert] with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jc_ca"

let telesec = read_cert "telesec"
let jfd = [ read_cert "jabber.fu-berlin.de" ; read_cert "fu-berlin" ; read_cert "dfn" ]

let test_jfd_ca () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.fu-berlin.de") ~time ~anchors:[telesec] (jfd@[telesec]) with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jfd_ca"

let test_jfd_ca' () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.fu-berlin.de") ~time ~anchors:[telesec] jfd with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jfd_ca'"

let test_izenpe () =
  let crt = read_cert "izenpe" in
  let _, san = Extension.(get Subject_alt_name (Certificate.extensions crt)) in
  Alcotest.(check int "two SAN (mail + dir)" 2 (General_name.cardinal san));
  Alcotest.(check (list string) "mail in SAN is correct" [ "info@izenpe.com" ]
              General_name.(get Rfc_822 san));
  let dir = General_name.(get Directory san) in
  Alcotest.(check int "directory san len is 1" 1 (List.length dir));
  let data = Fmt.to_to_string Distinguished_name.pp (List.hd dir) in
  let expected = "/O=IZENPE S.A. - CIF A01337260-RMerc.Vitoria-Gasteiz T1055 F62 S8/Street=Avda del Mediterraneo Etorbidea 14 - 01010 Vitoria-Gasteiz" in
  Alcotest.(check string "directory in SAN is correct" expected data)

let test_name_constraints () =
  ignore (read_cert "name-constraints")

let dn_ok description = function
  | Ok value -> value
  | Error (`Msg message) -> Alcotest.failf "%s: %s" description message

let dn_error description = function
  | Error (`Msg _) -> ()
  | Ok _ -> Alcotest.failf "%s: expected rejection" description

let check_dn =
  (module Distinguished_name: Alcotest.TESTABLE with type t = Distinguished_name.t)

let test_distinguished_name () =
  let open Distinguished_name in
  let crt = read_cert "PostaCARoot" in
  let expected = [
    Relative_distinguished_name.singleton (DC (Encoded_string.of_string ~encoding:`IA5 "rs")) ;
    Relative_distinguished_name.singleton (DC (Encoded_string.of_string ~encoding:`IA5 "posta")) ;
    Relative_distinguished_name.singleton (DC (Encoded_string.of_string ~encoding:`IA5 "ca")) ;
    Relative_distinguished_name.singleton (CN (Common_name.v "Configuration")) ;
    Relative_distinguished_name.singleton (CN (Common_name.v "Services")) ;
    Relative_distinguished_name.singleton (CN (Common_name.v "Public Key Services")) ;
    Relative_distinguished_name.singleton (CN (Common_name.v "AIA")) ;
    Relative_distinguished_name.singleton (CN (Common_name.v "Posta CA Root"))
  ] in
  Alcotest.(check check_dn "complex issuer is good"
              expected (Certificate.issuer crt)) ;
  Alcotest.(check check_dn "complex subject is good"
              expected (Certificate.subject crt))

let test_common_name_lookup () =
  let open Distinguished_name in
  let rdn = Relative_distinguished_name.of_list in
  let check description expected name =
    Alcotest.(check (option string) description expected
                (Option.map Common_name.to_string (common_name name)))
  in
  let attributes = [
    CN (Common_name.v "a.example");
    O (Organization_name.v "Example");
    OU (Organizational_unit_name.v "Unit");
    L (Locality_name.v "London")
  ] in
  List.iter (fun attributes ->
      let set = List.fold_left (fun set attribute ->
          Relative_distinguished_name.add attribute set)
          Relative_distinguished_name.empty attributes in
      check "CN in a multi-valued RDN" (Some "a.example") [set])
    [attributes; List.rev attributes];
  check "empty name" None [];
  check "empty RDN" None [rdn []];
  check "no CN" None [rdn [O (Organization_name.v "Example")]];
  check "most specific CN" (Some "b")
    [rdn [CN (Common_name.v "a")]; rdn [CN (Common_name.v "b")];
     rdn [O (Organization_name.v "Example")]];
  check "multiple CN values" (Some "a")
    [rdn [CN (Common_name.v "z"); CN (Common_name.v "a")]]

let test_distinguished_name_pp () =
  let module Dn = struct
    include Distinguished_name
    let cn s = Relative_distinguished_name.singleton (CN (Common_name.v s))
    let o s = Relative_distinguished_name.singleton (O (Organization_name.v s))
    let initials s =
      Relative_distinguished_name.singleton (Initials (Personal_name.v s))
    let (+) = Relative_distinguished_name.union
  end in
  let dn1 = "DN1", Dn.[o "Blanc";
                       cn "John Doe" + initials "J.D." + initials "N.N."] in
  let dn2 = "DN2", Dn.[o " Escapist"; cn "# 2"; cn " \"+,;/<>\\  "] in
  let pp1 = "RFC4514", Fmt.hbox (Dn.make_pp ~format:`RFC4514 ()) in
  let pp2 = "RFC4514-spacy",
    Fmt.hbox (Dn.make_pp ~format:`RFC4514 ~spacing:`Loose ()) in
  let pp3 = "OpenSSL", Fmt.hbox (Dn.make_pp ~format:`OpenSSL ()) in
  let pp4 = "OSF", Fmt.hbox (Dn.make_pp ~format:`OSF ()) in
  let pp5 = "RFC4514-vbox", Fmt.vbox (Dn.make_pp ~format:`RFC4514 ()) in
  let check (pp_desc, pp) (dn_desc, dn) expected =
    Alcotest.(check string) (Printf.sprintf "%s %s" pp_desc dn_desc)
      expected (Fmt.to_to_string pp dn)
  in
  check pp1 dn1 {|CN=John Doe+Initials=J.D.+Initials=N.N.,O=Blanc|} ;
  check pp1 dn2 {|CN=\ \"\+\,\;/\<\>\\ \ ,CN=\# 2,O=\ Escapist|} ;
  check pp2 dn1 {|CN = John Doe + Initials = J.D. + Initials = N.N., O = Blanc|} ;
  check pp2 dn2 {|CN = \ \"\+\,\;/\<\>\\ \ , CN = \# 2, O = \ Escapist|} ;
  check pp3 dn1 {|O = Blanc, CN = John Doe + Initials = J.D. + Initials = N.N.|} ;
  check pp3 dn2 {|O = \ Escapist, CN = \# 2, CN = \ \"\+\,\;/\<\>\\ \ |} ;
  check pp4 dn1 {|/O=Blanc/CN=John Doe+Initials=J.D.+Initials=N.N.|} ;
  check pp4 dn2 {|/O=\ Escapist/CN=\# 2/CN=\ \"\+,;\/\<\>\\ \ |} ;
  check pp5 dn1 "CN=John Doe+\nInitials=J.D.+\nInitials=N.N.,\nO=Blanc"

let decode_name der =
  match Distinguished_name.decode_der der with
  | Ok dn -> dn
  | Error (`Msg msg) -> Alcotest.failf "name decoding error: %s" msg

let test_encoded_name_roundtrip () =
  let open Distinguished_name in
  (* These are content octets, not text passed through a tag-specific encoder.
     In particular, A is two bytes in BMPString and four in UniversalString. *)
  List.iter (fun (encoding, octets, hex) ->
      let der = Ohex.decode hex in
      let dn = decode_name der in
      Alcotest.(check string "name DER" der (encode_der dn)) ;
      match common_name dn with
      | None -> Alcotest.fail "missing CN"
      | Some value ->
        Alcotest.(check string "CN content octets" octets
                    (Common_name.to_string value)) ;
        Alcotest.(check bool ("CN tag in " ^ hex) true
                    (encoding = Encoded_string.encoding (Common_name.encoded value))))
    [ `UTF8, "A", "300c310a300806035504030c0141" ;
      `UTF8, "\xc3\xa9", "300d310b300906035504030c02c3a9" ;
      `Printable, "A", "300c310a30080603550403130141" ;
      `Teletex, "A", "300c310a30080603550403140141" ;
      `Universal, "\x00\x00\x00A", "300f310d300b06035504031c0400000041" ;
      `BMP, "\x00A", "300d310b300906035504031e020041" ] ;
  dn_error "IA5String is not a DirectoryString"
    (decode_der (Ohex.decode "300c310a30080603550403160141")) ;
  let fresh = [Relative_distinguished_name.singleton
                 (CN (Common_name.v "A"))] in
  Alcotest.(check string "fresh CN defaults to UTF8String"
              (Ohex.decode "300c310a300806035504030c0141") (encode_der fresh))

(* DER fixtures are assembled independently of the library's name encoder. *)
let der_tlv tag contents =
  let octet n = String.make 1 (Char.chr n) in
  let length = String.length contents in
  assert (length < 128) ;
  octet tag ^ octet length ^ contents

let attribute_der oid tag octets =
  der_tlv 0x30 (der_tlv 0x31
      (der_tlv 0x30 (der_tlv 0x06 (Ohex.decode oid) ^ der_tlv tag octets)))

let directory_attributes =
  let open Distinguished_name in
  [ "CN", "550403", (fun ?encoding x -> CN (Common_name.v ?encoding x)) ;
    "L", "550407", (fun ?encoding x -> L (Locality_name.v ?encoding x)) ;
    "ST", "550408", (fun ?encoding x -> ST (State_or_province_name.v ?encoding x)) ;
    "O", "55040a", (fun ?encoding x -> O (Organization_name.v ?encoding x)) ;
    "OU", "55040b", (fun ?encoding x -> OU (Organizational_unit_name.v ?encoding x)) ;
    "T", "55040c", (fun ?encoding x -> T (Title.v ?encoding x)) ;
    "Given_name", "55042a", (fun ?encoding x -> Given_name (Personal_name.v ?encoding x)) ;
    "Surname", "550404", (fun ?encoding x -> Surname (Personal_name.v ?encoding x)) ;
    "Initials", "55042b", (fun ?encoding x -> Initials (Personal_name.v ?encoding x)) ;
    "Pseudonym", "550441", (fun ?encoding x -> Pseudonym (Pseudonym.v ?encoding x)) ;
    "Generation", "55042c", (fun ?encoding x -> Generation (Personal_name.v ?encoding x)) ;
    "Street", "550409", (fun ?encoding x -> Street (Street_address.v ?encoding x)) ;
    "Userid", "0992268993f22c640101", (fun ?encoding x -> Userid (User_id.v ?encoding x)) ]

let test_attribute_encodings () =
  let open Distinguished_name in
  let check_attribute description oid tag octets attribute =
    let der = attribute_der oid tag octets in
    let expected = [Relative_distinguished_name.singleton attribute] in
    let decoded = decode_name der in
    Alcotest.(check string (description ^ ": constructed DER") der (encode_der expected)) ;
    Alcotest.(check string (description ^ ": parsed DER") der (encode_der decoded))
  in
  (* BMPString is permitted for DirectoryString attributes, not fixed-string schemas. *)
  List.iter (fun (description, oid, attribute) ->
      check_attribute description oid 0x0c "A" (attribute ?encoding:None "A") ;
      check_attribute description oid 0x1e "\x00A" (attribute ?encoding:(Some `BMP) "\x00A"))
    directory_attributes ;
  let fixed = [
    "Serialnumber", "550405", 0x13, "A", Serialnumber (Serial_number.v "A") ;
    "C", "550406", 0x13, "GB", C (Country_name.v "GB") ;
    "DNQ", "55042e", 0x13, "A", DNQ (Encoded_string.of_string ~encoding:`Printable "A") ;
    "Mail", "2a864886f70d010901", 0x16, "a@example.com", Mail (Email_address.v "a@example.com") ;
    "DC", "0992268993f22c640119", 0x16, "A", DC (Encoded_string.of_string ~encoding:`IA5 "A")
  ] in
  List.iter (fun (description, oid, tag, octets, attribute) ->
      check_attribute description oid tag octets attribute)
    fixed ;
  dn_error "Country requires PrintableString"
    (decode_der (attribute_der "550406" 0x0c "GB")) ;
  dn_error "Mail requires IA5String"
    (decode_der (attribute_der "2a864886f70d010901" 0x13 "A"))

let test_other_attributes () =
  let open Distinguished_name in
  let other_oid = Asn.OID.(base 1 2 <| 3 <| 4) in
  let known_oids =
    List.map (fun arc -> Asn.OID.(base 2 5 <| 4 <| arc), `Printable)
      [3; 5; 6; 7; 8; 10; 11; 12; 46; 42; 4; 43; 65; 44; 9] @
    Asn.OID.[(base 1 2 <| 840 <| 113549 <| 1 <| 9 <| 1), `IA5 ;
             (base 0 9 <| 2342 <| 19200300 <| 100 <| 1 <| 25), `IA5 ;
             (base 0 9 <| 2342 <| 19200300 <| 100 <| 1 <| 1), `Printable]
  in
  List.iter (fun (oid, encoding) ->
      let value = Encoded_string.of_string ~encoding "GB" in
      dn_error (Fmt.str "known OID %a cannot use Other" Asn.OID.pp oid)
        (Other_attribute.create oid value))
    known_oids ;
  List.iter (fun (encoding, tag, octets) ->
      let value = Encoded_string.of_string ~encoding octets in
      let other = dn_ok "unknown attribute" (Other_attribute.create other_oid value) in
      let name = [Relative_distinguished_name.singleton (Other other)] in
      let der = attribute_der "2a0304" tag octets in
      let decoded = decode_name der in
      Alcotest.(check string "Other independently constructed DER" der (encode_der name)) ;
      Alcotest.(check string "Other DER roundtrip" der (encode_der decoded)))
    [ `UTF8, 0x0c, "\xc3\xa9" ;
      `Printable, 0x13, "A" ;
      `IA5, 0x16, "@_" ;
      `Teletex, 0x14, "A" ;
      `Universal, 0x1c, "\x00\x00\x00A" ;
      `BMP, 0x1e, "\x00A" ]

let test_name_matching_and_storage () =
  let open Distinguished_name in
  let utf8 = CN (Common_name.v "A")
  and printable = CN (Common_name.v ~encoding:`Printable "A")
  and bmp = CN (Common_name.v ~encoding:`BMP "\x00A") in
  let rdn = Relative_distinguished_name.singleton in
  let name attr = [rdn attr] in
  Alcotest.(check bool "tag-agnostic matching" true
              (Distinguished_name.equal (name utf8) (name printable))) ;
  Alcotest.(check bool "RDN sets distinguish tags" false
              (Relative_distinguished_name.equal (rdn utf8) (rdn printable))) ;
  Alcotest.(check bool "matching does not transcode BMPString" false
              (Distinguished_name.equal (name utf8) (name bmp))) ;
  let mixed_der = Ohex.decode "30163114300806035504030c014130080603550403130141" in
  let mixed = decode_name mixed_der in
  (match mixed with
   | [rdn] ->
     Alcotest.(check int "tag-only duplicates survive in storage" 2
                 (Relative_distinguished_name.cardinal rdn))
   | _ -> Alcotest.fail "expected one multi-valued RDN") ;
  Alcotest.(check string "multi-valued RDN DER" mixed_der (encode_der mixed)) ;
  Alcotest.(check bool "matching collapses tag-only duplicates" true
              (Distinguished_name.equal mixed (name printable))) ;
  let organization = name (O (Organization_name.v "Example")) in
  Alcotest.(check bool "RDN order still matters" false
              (Distinguished_name.equal (organization @ name utf8) (name utf8 @ organization)))

let test_yubico () =
  ignore (read_cert "yubico")

let test_frac_s () =
  let file = "until_frac_s" in
  match Certificate.decode_pem (regression file) with
  | Ok _ -> Alcotest.failf "certificate %s, expected decoding error" file
  | Error (`Msg _) -> ()

let decode_valid_pem file =
  let data = regression file in
  match Private_key.decode_pem data with
   | Ok _ -> ()
   | Error (`Msg _) ->
     Alcotest.failf "private key %s failed to be verified" file

let test_gcloud_key () =
  (* discussion in https://github.com/mirage/mirage-crypto/issues/62 *)
  let file = "gcloud" in
  decode_valid_pem file

let test_openssl_2048_key () =
  (* this key has a d > lcm (p - 1) (q - 1) *)
  let file = "openssl_2048" in
  decode_valid_pem file

let ed25519_priv =
  Ohex.decode "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842"

let ed25519_priv_key () =
  let data =
    {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----
|}
  in
  match Private_key.decode_pem data with
  | Ok (`ED25519 k as ke) when String.equal ed25519_priv (Mirage_crypto_ec.Ed25519.priv_to_octets k) ->
    let encoded = Private_key.encode_pem ke in
    if not (String.equal encoded data) then
      Alcotest.failf "ED25519 encoding failed"
  | Ok (`ED25519 _) -> Alcotest.failf "wrong ED25519 private key"
  | Ok _ | Error (`Msg _) -> Alcotest.failf "ED25519 private key decode failure"

let ed25519_pub_key () =
  let data =
    {|-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
|}
  and pub =
    match Mirage_crypto_ec.Ed25519.priv_of_octets ed25519_priv with
    | Error _ -> Alcotest.fail "couldn't decode private Ed25519 key"
    | Ok p ->
      match Private_key.public (`ED25519 p) with
      | `ED25519 p -> p
      | _ -> Alcotest.fail "couldn't convert private Ed25519 key to public"
  in
  let to_cs = Mirage_crypto_ec.Ed25519.pub_to_octets in
  match Public_key.decode_pem data with
  | Ok (`ED25519 k) when String.equal (to_cs pub) (to_cs k) ->
    let encoded = Public_key.encode_pem (`ED25519 k) in
    if not (String.equal encoded data) then
      Alcotest.failf "ED25519 public key encoding failure"
  | _ -> Alcotest.failf "bad ED25519 public key"

let p384_key () =
  let priv_data = {|-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDzBTbwp91ON4CNuDE+
pjKsehNV7I3eTpyKpMlSUqHAguO8hK+t28A/730TP2L0rPyhZANiAATZbEoUICtu
yXyN4G6DDHaUHwwe2bfcsTvY9LnlLCPvu24JTuGjf7pT2faiuvjGb49jk8C2KJWt
0DISTEJ945y41DY0cIPl1okaN+E3yJ66kKpJ0XeKoOJ0rTTopazzjzI=
-----END PRIVATE KEY-----
|}
  and pub_data = {|-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE2WxKFCArbsl8jeBugwx2lB8MHtm33LE7
2PS55Swj77tuCU7ho3+6U9n2orr4xm+PY5PAtiiVrdAyEkxCfeOcuNQ2NHCD5daJ
GjfhN8ieupCqSdF3iqDidK006KWs848y
-----END PUBLIC KEY-----
|}
  in
  match
    Private_key.decode_pem priv_data,
    Public_key.decode_pem pub_data
  with
  | Ok (`P384 priv), Ok (`P384 pub) ->
    let to_cs = Mirage_crypto_ec.P384.Dsa.pub_to_octets in
    let pub' = Mirage_crypto_ec.P384.Dsa.pub_of_priv priv in
    Alcotest.(check bool __LOC__ true (String.equal (to_cs pub) (to_cs pub')));
    let pub_data' = Public_key.encode_pem (`P384 pub) in
    Alcotest.(check bool __LOC__ true
                (String.equal pub_data pub_data'));
    let priv_data' = Private_key.encode_pem (`P384 priv) in
    begin match Private_key.decode_pem priv_data' with
      | Ok (`P384 priv) ->
        let pub' = Mirage_crypto_ec.P384.Dsa.pub_of_priv priv in
        Alcotest.(check bool __LOC__ true
                    (String.equal (to_cs pub) (to_cs pub')))
      | _ -> Alcotest.failf "cannot decode re-encoded P384 private key"
    end
  | _ -> Alcotest.failf "bad P384 key"

let ed25519_cert () =
  let file = "example-25519" in
  match Certificate.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "ED25519 certificate %s, decoding error %s" file msg
  | Ok cert ->
    match Validation.valid_ca cert with
    | Error e ->
      Alcotest.failf "verifying 25519 ca certificate failed %a"
        Validation.pp_ca_error e
    | Ok () ->
      match Validation.verify_chain ~host:(host "www.example.com") ~time ~anchors:[cert] [cert] with
      | Ok _ -> ()
      | Error e ->
        Alcotest.failf "verifying 25519 certificate failed %a"
          Validation.pp_chain_error e

let le_p384_root () =
  let file = "letsencrypt-root-x2" in
  match Certificate.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "let's encrypt P384 certificate %s, decoding error %s"
      file msg
  | Ok cert ->
    match Validation.valid_ca cert with
    | Error e ->
      Alcotest.failf "verifying P384 ca certificate failed %a"
        Validation.pp_ca_error e
    | Ok () -> ()

let p256_key () =
  let file = "priv_p256" in
  match Private_key.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "private P256 key %s decoding error %s" file msg
  | Ok _ -> ()

let ip_address () =
  let c = read_cert "1.1.1.1" in
  let ta = read_cert "digicert" in
  match
    Validation.verify_chain ~ip:(Ipaddr.of_string_exn "1.1.1.1")
      ~host:None ~time:(fun () -> None) ~anchors:[ta] [c]
  with
  | Ok _ -> ()
  | Error ce -> Alcotest.failf "validation of IP address failed: %a"
                  Validation.pp_chain_error ce

let alternate_sha1rsa_oid () =
  let file = "alternate-sha1rsa-oid" in
  match Certificate.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "alternate SHA1RSA OID certificate %s, decoding error %s" file msg
  | Ok _cert -> ()

let p256_sha384 () =
  let file = "p256_sha384" in
  match Certificate.decode_pem (regression file) with
  | Error (`Msg msg) ->
    Alcotest.failf "P256 certificate with SHA384 %s, decoding error %s"
      file msg
  | Ok cert ->
    match Validation.valid_ca cert with
    | Error e ->
      Alcotest.failf "verifying P256 certificate failed %a"
        Validation.pp_ca_error e
    | Ok () -> ()

let rsa_pub () =
  let file = "rsa_pub" in
  let data = regression file in
  match Public_key.decode_pem data with
  | Error (`Msg msg) ->
    Alcotest.failf "RSA public key %s, decoding error %s" file msg
  | Ok pub ->
    let pem = Public_key.encode_pem pub in
    Alcotest.(check string "PEM encoding of RSA public key is identical"
                data pem)

let rsa_priv () =
  let file = "rsa_priv" in
  let data = regression file in
  match Private_key.decode_pem data with
  | Error (`Msg msg) ->
    Alcotest.failf "RSA private key %s, decoding error %s" file msg
  | Ok priv ->
    let pem = Private_key.encode_pem priv in
    Alcotest.(check string "PEM encoding of RSA private key is identical"
                data pem);
    let pub = regression "rsa_pub" in
    Alcotest.(check string "PEM encoding of RSA public key (derived from private key) is identical"
                pub (Public_key.encode_pem (Private_key.public priv)))

let ec_pub file () =
  let data = regression file in
  match Public_key.decode_pem data with
  | Error (`Msg msg) ->
    Alcotest.failf "EC public key %s, decoding error %s" file msg
  | Ok pub ->
    let pem = Public_key.encode_pem pub in
    Alcotest.(check string "PEM encoding of EC public key is identical"
                data pem)

let ec_priv file pub_file () =
  let data = regression file in
  match Private_key.decode_pem data with
  | Error (`Msg msg) ->
    Alcotest.failf "EC private key %s, decoding error %s" file msg
  | Ok priv ->
    let pem = Private_key.encode_pem priv in
    Alcotest.(check string "PEM encoding of EC private key is identical"
                data pem);
    let pub = regression pub_file in
    Alcotest.(check string "PEM encoding of EC public key (derived from private key) is identical"
                pub (Public_key.encode_pem (Private_key.public priv)))

let sign_with_intermediate () =
  let key () = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:1024 ())
  and name ?encoding value =
    Distinguished_name.[Relative_distinguished_name.singleton
                          (CN (Common_name.v ?encoding value))]
  and get what = function
    | Ok value -> value
    | Error _ -> Alcotest.fail ("couldn't " ^ what)
  in
  let valid_from = Ptime.epoch in
  let valid_until = match Ptime.add_span valid_from (Ptime.Span.of_int_s 3600) with
    | Some time -> time
    | None -> assert false
  in
  let ca_extensions = Extension.(
      add Key_usage (true, [`Key_cert_sign])
        (singleton Basic_constraints (true, (true, None))))
  and leaf_extensions = Extension.(
      add Key_usage (true, [`Digital_signature; `Key_encipherment])
        (add Ext_key_usage (true, [`Server_auth])
           (singleton Basic_constraints (true, (false, None)))))
  in
  let sign_ca subject subject_key issuer_key issuer =
    let request = Signing_request.create subject subject_key |> get "create CA CSR" in
    Signing_request.sign request ~valid_from ~valid_until
      ~extensions:ca_extensions issuer_key issuer |> get "sign CA certificate"
  in
  let root_key = key ()
  and intermediate_key = key () in
  let root = sign_ca (name "root") root_key root_key (name "root") in
  let intermediate =
    sign_ca (name ~encoding:`Printable "intermediate") intermediate_key root_key
      (Certificate.subject root)
  in
  let intermediate = Certificate.decode_der (Certificate.encode_der intermediate)
                     |> get "decode intermediate" in
  let request = Signing_request.create (name ~encoding:`Printable "leaf.example") (key ())
                |> get "create leaf CSR" in
  let request = Signing_request.decode_der (Signing_request.encode_der request)
                |> get "decode leaf CSR" in
  let leaf =
    Signing_request.sign_certificate request ~valid_from ~valid_until
      ~extensions:leaf_extensions intermediate_key intermediate |> get "sign leaf"
  in
  let leaf = Certificate.decode_der (Certificate.encode_der leaf) |> get "decode leaf" in
  Alcotest.(check string "intermediate subject encoding"
              (Ohex.decode "3017311530130603550403130c696e7465726d656469617465")
              (Distinguished_name.encode_der (Certificate.issuer leaf)));
  Alcotest.(check string "leaf subject encoding"
              (Ohex.decode "3017311530130603550403130c6c6561662e6578616d706c65")
              (Distinguished_name.encode_der (Certificate.subject leaf)));
  let hostnames = Alcotest.testable Host.Set.pp Host.Set.equal in
  let expected = Host.Set.singleton
      (`Strict, Domain_name.host_exn (Domain_name.of_string_exn "leaf.example")) in
  Alcotest.check hostnames "CSR hostname fallback" expected (Signing_request.hostnames request);
  Alcotest.check hostnames "certificate hostname fallback" expected (Certificate.hostnames leaf);
  let dn = Alcotest.testable Distinguished_name.pp Distinguished_name.equal in
  Alcotest.check dn "issuer is intermediate subject"
    (Certificate.subject intermediate) (Certificate.issuer leaf);
  match Validation.verify_chain ~host:None ~time ~anchors:[root] [leaf; intermediate] with
  | Ok _ -> ()
  | Error error -> Alcotest.failf "expected chain to validate: %a"
                     Validation.pp_chain_error error

let regression_tests = [
  "Sign with an intermediate CA", `Quick, sign_with_intermediate ;
  "RSA: key too small (jc_jc)", `Quick, test_jc_jc ;
  "jc_ca", `Quick, test_jc_ca_fail ;
  "jc_ca", `Quick, test_jc_ca_all_hashes ;
  "jfd_ca", `Quick, test_jfd_ca ;
  "jfd_ca'", `Quick, test_jfd_ca' ;
  "SAN dir explicit or implicit", `Quick, test_izenpe ;
  "name constraint parsing (DNS: .gr)", `Quick, test_name_constraints ;
  "complex distinguished name", `Quick, test_distinguished_name ;
  "common name lookup", `Quick, test_common_name_lookup ;
  "distinguished name pp", `Quick, test_distinguished_name_pp ;
  "encoded name roundtrip", `Quick, test_encoded_name_roundtrip ;
  "attribute string encodings", `Quick, test_attribute_encodings ;
  "unknown and reserved attribute OIDs", `Quick, test_other_attributes ;
  "name matching and storage", `Quick, test_name_matching_and_storage ;
  "algorithm without null", `Quick, test_yubico ;
  "valid until generalized_time with fractional seconds", `Quick, test_frac_s ;
  "parse valid key where 1 <> d * e mod (p - 1) * (q - 1)", `Quick, test_gcloud_key ;
  "parse valid key where d <> e ^ -1 mod lcm ((p - 1) (q - 1))", `Quick, test_openssl_2048_key ;
  "ed25519 private key", `Quick, ed25519_priv_key ;
  "ed25519 public key", `Quick, ed25519_pub_key ;
  "p384 key", `Quick, p384_key ;
  "ed25519 certificate", `Quick, ed25519_cert ;
  "p384 certificate", `Quick, le_p384_root ;
  "p256 key", `Quick, p256_key ;
  "ip_address", `Quick, ip_address ;
  "alternative SHA1RSA OID", `Quick, alternate_sha1rsa_oid;
  "p256 with sha384", `Quick, p256_sha384 ;
  "rsa public key", `Quick, rsa_pub ;
  "rsa private key", `Quick, rsa_priv ;
] @ List.flatten (List.map (fun file ->
    [ "public " ^ file, `Quick, ec_pub ("pub_" ^ file) ;
      "private " ^ file, `Quick, ec_priv ("priv_" ^ file) ("pub_" ^ file)
    ]) [ "p521" ; "p384" ; "p256_2" ])

let host_set_test =
  let module M = struct
    type t = Host.Set.t
    let pp ppf hs =
      let pp_one ppf (typ, name) =
        Fmt.pf ppf "%s%a"
          (match typ with `Strict -> "" | `Wildcard -> "*.")
          Domain_name.pp name
      in
      Fmt.(list ~sep:(any ", ") pp_one) ppf (Host.Set.elements hs)
    let equal = Host.Set.equal
  end in (module M: Alcotest.TESTABLE with type t = M.t)

let cert_hostnames cert names () =
  Alcotest.check host_set_test __LOC__ (Certificate.hostnames cert) names

let csr file =
  let data = mmap ("./csr/" ^ file ^ ".pem") in
  match Signing_request.decode_pem data with
  | Ok csr -> csr
  | Error (`Msg m) ->
    Alcotest.failf "signing request %s decoding error %s" file m

let csr_hostnames cert names () =
  Alcotest.check host_set_test __LOC__ (Signing_request.hostnames cert) names

let host_set xs =
  Host.Set.of_list
    (List.map (fun n -> `Strict, Domain_name.(host_exn (of_string_exn n))) xs)

let hostname_tests = [
  "cacert hostnames", `Quick, cert_hostnames cacert Host.Set.empty;
  "izenpe hostnames", `Quick, cert_hostnames (read_cert "izenpe") (host_set ["izenpe.com"]);
  "jabber.ccc.de hostnames", `Quick, cert_hostnames jc (host_set [ "jabber.ccc.de" ; "conference.jabber.ccc.de" ; "jabberd.jabber.ccc.de" ; "pubsub.jabber.ccc.de" ; "vjud.jabber.ccc.de" ]);
  "jaber.fu-berlin.de hostnames", `Quick, cert_hostnames (read_cert "jabber.fu-berlin.de") (host_set [ "jabber.fu-berlin.de" ; "conference.jabber.fu-berlin.de" ; "proxy.jabber.fu-berlin.de" ; "echo.jabber.fu-berlin.de" ; "file.jabber.fu-berlin.de" ; "jitsi-videobridge.jabber.fu-berlin.de" ; "multicast.jabber.fu-berlin.de" ; "pubsub.jabber.fu-berlin.de" ]);
  "pads.ccc.de hostnames", `Quick, cert_hostnames (read_cert "pads.ccc.de") (Host.Set.add (`Wildcard, Domain_name.(host_exn (of_string_exn "pads.ccc.de"))) (host_set ["pads.ccc.de"]));
  "first hostnames", `Quick, cert_hostnames (read_cert "first") (host_set ["foo.foobar.com"; "foobar.com"]);
  "CSR your_new_domain hostnames", `Quick, csr_hostnames (csr "your-new-domain") (host_set ["your-new-domain.com" ; "www.your-new-domain.com"]);
  "CSR your_new_domain_raw hostnames", `Quick, csr_hostnames (csr "your-new-domain-raw") (host_set ["your-new-domain.com" ; "www.your-new-domain.com"]);
  "CSR bar.com hostnames", `Quick, csr_hostnames (csr "wild-bar") (Host.Set.add (`Wildcard, Domain_name.(host_exn (of_string_exn "bar.com"))) (host_set ["your-new-domain.com" ; "www.your-new-domain.com"]));
  "CSR foo.com hostnames", `Quick, csr_hostnames (csr "wild-foo-cn") (Host.Set.singleton (`Wildcard, Domain_name.(host_exn (of_string_exn "foo.com"))));
]

let dns_subject_alt_names names =
  let names = General_name.singleton General_name.DNS names in
  Extension.add Extension.Subject_alt_name (false, names) Utils.leaf_exts

let dns_name_constraints ~permitted ~excluded =
  let subtrees names =
    List.map (fun name -> General_name.B (General_name.DNS, [name]), 0, None) names
  in
  Extension.add Extension.Name_constraints
    (true, (subtrees permitted, subtrees excluded)) (Utils.ca_exts ())

let name_constraints_union () =
  let now = Ptime_clock.now () in
  let extensions =
    dns_name_constraints ~permitted:["example.com" ; "example.net"] ~excluded:[]
  in
  let _, capriv = Utils.key () in
  let ca = Utils.selfsigned ~now ~priv:capriv extensions in
  let _, priv = Utils.key () in
  List.iter (fun name ->
      let example =
        Utils.cert ~now ~ca_key:capriv ~priv ~name:(Utils.cn name) Utils.leaf_exts (Certificate.subject ca)
      in
      match Validation.verify_chain ~host:None ~time ~anchors:[ca] [example] with
      | Ok _ -> ()
      | Error _ -> Alcotest.fail "expected permitted name to validate")
    ["www.example.com" ; "www.example.net"] ;
  let other =
    Utils.cert ~now ~ca_key:capriv ~priv ~name:(Utils.cn "www.other.org") Utils.leaf_exts (Certificate.subject ca)
  in
  match Validation.verify_chain ~host:None ~time ~anchors:[ca] [other] with
  | Error (`Msg "domain name is not permitted") -> ()
  | Error _ -> Alcotest.fail "expected a name constraint error"
  | Ok _ -> Alcotest.fail "expected other name to be rejected"

let name_constraints_all_dns_names () =
  let now = Ptime_clock.now () in
  let extensions =
    dns_name_constraints ~permitted:["example.com" ; "example.net"] ~excluded:[]
  in
  let _, capriv = Utils.key () in
  let ca = Utils.selfsigned ~now ~priv:capriv extensions in
  let _, priv = Utils.key () in
  List.iter (fun (names, allowed) ->
      let extensions = dns_subject_alt_names names in
      let leaf =
        Utils.cert ~now ~ca_key:capriv ~priv ~name:(Utils.cn "unused.invalid")
          extensions (Certificate.subject ca)
      in
      match Validation.verify_chain ~host:None ~time ~anchors:[ca] [leaf], allowed with
      | Ok _, true -> ()
      | Error (`Msg "domain name is not permitted"), false -> ()
      | _ -> Alcotest.failf "unexpected validation result for DNS SANs %s"
               (String.concat ", " names))
    [ ["www.example.com"], true ;
      ["www.example.net"], true ;
      ["www.example.com" ; "www.example.net"], true ;
      ["www.example.com" ; "www.other.org"], false ]

let name_constraints_excluded () =
  let now = Ptime_clock.now () in
  let extensions =
    dns_name_constraints ~permitted:["example.com" ; "example.net"]
      ~excluded:["blocked.example.com"]
  in
  let _, capriv = Utils.key () in
  let ca = Utils.selfsigned ~now ~priv:capriv extensions in
  let _, priv = Utils.key () in
  List.iter (fun (name, allowed) ->
      let extensions = dns_subject_alt_names [name] in
      let leaf =
        Utils.cert ~now ~ca_key:capriv ~priv extensions (Certificate.subject ca)
      in
      match Validation.verify_chain ~host:None ~time ~anchors:[ca] [leaf], allowed with
      | Ok _, true -> ()
      | Error (`Msg "domain name is excluded"), false -> ()
      | _ -> Alcotest.failf "unexpected validation result for %s" name)
    [ "www.example.com", true ;
      "www.example.net", true ;
      "blocked.example.com", false ;
      "www.blocked.example.com", false ]

let name_constraints_chain () =
  let now = Ptime_clock.now () in
  let root_extensions =
    dns_name_constraints ~permitted:["example.com" ; "example.net"] ~excluded:[]
  and intermediate_extensions =
    dns_name_constraints ~permitted:["example.com" ; "example.org"] ~excluded:[]
  in
  let _, root_priv = Utils.key () in
  let root =
    Utils.selfsigned ~now ~priv:root_priv ~name:(Utils.cn "root") root_extensions
  in
  let _, intermediate_priv = Utils.key () in
  let intermediate =
    Utils.cert ~now ~ca_key:root_priv ~priv:intermediate_priv
      ~name:(Utils.cn "intermediate") intermediate_extensions
      (Certificate.subject root)
  in
  let _, priv = Utils.key () in
  List.iter (fun (name, allowed) ->
      let extensions = dns_subject_alt_names [name] in
      let leaf =
        Utils.cert ~now ~ca_key:intermediate_priv ~priv extensions
          (Certificate.subject intermediate)
      in
      match Validation.verify_chain ~host:None ~time ~anchors:[root]
              [leaf ; intermediate], allowed with
      | Ok _, true -> ()
      | Error (`Msg "domain name is not permitted"), false -> ()
      | _ -> Alcotest.failf "unexpected validation result for %s" name)
    [ "www.example.com", true ;
      "www.example.net", false ;
      "www.example.org", false ]

let ip_name_constraints_union () =
  let now = Ptime_clock.now () in
  (* 192.0.2.0/24 and 198.51.100.0/24, encoded as address followed by mask. *)
  let permitted =
    List.map (fun prefix ->
        General_name.B (General_name.IP, [Ohex.decode prefix]), 0, None)
      ["c0000200ffffff00" ; "c6336400ffffff00"]
  in
  let extensions =
    Extension.add Extension.Name_constraints (true, (permitted, [])) (Utils.ca_exts ())
  in
  let _, capriv = Utils.key () in
  let ca = Utils.selfsigned ~now ~priv:capriv extensions in
  let _, priv = Utils.key () in
  let verify addresses =
    let names = General_name.singleton General_name.IP (List.map Ohex.decode addresses) in
    let extensions = Extension.add Extension.Subject_alt_name (false, names) Utils.leaf_exts in
    let leaf =
      Utils.cert ~now ~ca_key:capriv ~priv extensions (Certificate.subject ca)
    in
    Validation.verify_chain ~host:None ~time ~anchors:[ca] [leaf]
  in
  List.iter (fun addresses ->
      match verify addresses with
      | Ok _ -> ()
      | Error _ -> Alcotest.fail "expected permitted IP addresses to validate")
    [["c0000201"] ; ["c6336401"] ; ["c0000201" ; "c6336401"]] ;
  match verify ["c0000201" ; "cb007101"] with
  | Error (`Msg "ip address is not permitted") -> ()
  | Error _ -> Alcotest.fail "expected an IP name constraint error"
  | Ok _ -> Alcotest.fail "expected outside IP address to be rejected"

let name_constraints_tests = [
  "Permitted name constraints form a union", `Quick, name_constraints_union ;
  "Permitted IP name constraints form a union", `Quick, ip_name_constraints_union ;
  "Every DNS SAN must be permitted", `Quick, name_constraints_all_dns_names ;
  "Excluded names take precedence", `Quick, name_constraints_excluded ;
  "Permitted names intersect across CAs", `Quick, name_constraints_chain ;
]
