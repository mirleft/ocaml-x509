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

let cert file =
  match Certificate.decode_pem (regression file) with
  | Ok cert -> cert
  | Error (`Msg m) -> Alcotest.failf "certificate %s decoding error %s" file m

let jc = cert "jabber.ccc.de"
let cacert = cert "cacert"

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

let telesec = cert "telesec"
let jfd = [ cert "jabber.fu-berlin.de" ; cert "fu-berlin" ; cert "dfn" ]

let test_jfd_ca () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.fu-berlin.de") ~time ~anchors:[telesec] (jfd@[telesec]) with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jfd_ca"

let test_jfd_ca' () =
  match Validation.verify_chain_of_trust ~host:(host "jabber.fu-berlin.de") ~time ~anchors:[telesec] jfd with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jfd_ca'"

let test_izenpe () =
  let crt = cert "izenpe" in
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
  ignore (cert "name-constraints")

let check_dn =
  (module Distinguished_name: Alcotest.TESTABLE with type t = Distinguished_name.t)

let test_distinguished_name () =
  let open Distinguished_name in
  let crt = cert "PostaCARoot" in
  let expected = [
    Relative_distinguished_name.singleton (DC "rs") ;
    Relative_distinguished_name.singleton (DC "posta") ;
    Relative_distinguished_name.singleton (DC "ca") ;
    Relative_distinguished_name.singleton (CN "Configuration") ;
    Relative_distinguished_name.singleton (CN "Services") ;
    Relative_distinguished_name.singleton (CN "Public Key Services") ;
    Relative_distinguished_name.singleton (CN "AIA") ;
    Relative_distinguished_name.singleton (CN "Posta CA Root")
  ] in
  Alcotest.(check check_dn "complex issuer is good"
              expected (Certificate.issuer crt)) ;
  Alcotest.(check check_dn "complex subject is good"
              expected (Certificate.subject crt))

let test_common_name_lookup () =
  let open Distinguished_name in
  let rdn = Relative_distinguished_name.of_list in
  let check description expected name =
    Alcotest.(check (option string) description expected (common_name name))
  in
  let attributes = [CN "a.example"; O "Example"; OU "Unit"; L "London"] in
  List.iter (fun attributes ->
      let set = List.fold_left (fun set attribute ->
          Relative_distinguished_name.add attribute set)
          Relative_distinguished_name.empty attributes in
      check "CN in a multi-valued RDN" (Some "a.example") [set])
    [attributes; List.rev attributes];
  check "empty name" None [];
  check "empty RDN" None [rdn []];
  check "no CN" None [rdn [O "Example"]];
  check "most specific CN" (Some "b")
    [rdn [CN "a"]; rdn [CN "b"]; rdn [O "Example"]];
  check "multiple CN values" (Some "a") [rdn [CN "z"; CN "a"]]

let test_distinguished_name_pp () =
  let module Dn = struct
    include Distinguished_name
    let cn s = Relative_distinguished_name.singleton (CN s)
    let o s = Relative_distinguished_name.singleton (O s)
    let initials s = Relative_distinguished_name.singleton (Initials s)
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

let test_yubico () =
  ignore (cert "yubico")

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
  | Ok priv, Ok pub ->
    Alcotest.(check bool __LOC__ true
      ("p384" = Key_type.to_string (Private_key.key_type priv)));
    Alcotest.(check bool __LOC__ true
      ("p384" = Key_type.to_string (Public_key.key_type pub)));
    let to_cs = Public_key.encode_der in
    let pub' = Private_key.public priv in
    Alcotest.(check bool __LOC__ true (String.equal (to_cs pub) (to_cs pub')));
    let pub_data' = Public_key.encode_pem pub in
    Alcotest.(check bool __LOC__ true
                (String.equal pub_data pub_data'));
    let priv_data' = Private_key.encode_pem priv in
    begin match Private_key.decode_pem priv_data' with
      | Ok priv ->
        let pub' = Private_key.public priv in
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
  let c = cert "1.1.1.1" in
  let ta = cert "digicert" in
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
  and name value =
    Distinguished_name.[Relative_distinguished_name.singleton (CN value)]
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
    sign_ca (name "intermediate") intermediate_key root_key (Certificate.subject root)
  in
  let request = Signing_request.create (name "leaf") (key ()) |> get "create leaf CSR" in
  let leaf =
    Signing_request.sign_certificate request ~valid_from ~valid_until
      ~extensions:leaf_extensions intermediate_key intermediate |> get "sign leaf"
  in
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
  "izenpe hostnames", `Quick, cert_hostnames (cert "izenpe") (host_set ["izenpe.com"]);
  "jabber.ccc.de hostnames", `Quick, cert_hostnames jc (host_set [ "jabber.ccc.de" ; "conference.jabber.ccc.de" ; "jabberd.jabber.ccc.de" ; "pubsub.jabber.ccc.de" ; "vjud.jabber.ccc.de" ]);
  "jaber.fu-berlin.de hostnames", `Quick, cert_hostnames (cert "jabber.fu-berlin.de") (host_set [ "jabber.fu-berlin.de" ; "conference.jabber.fu-berlin.de" ; "proxy.jabber.fu-berlin.de" ; "echo.jabber.fu-berlin.de" ; "file.jabber.fu-berlin.de" ; "jitsi-videobridge.jabber.fu-berlin.de" ; "multicast.jabber.fu-berlin.de" ; "pubsub.jabber.fu-berlin.de" ]);
  "pads.ccc.de hostnames", `Quick, cert_hostnames (cert "pads.ccc.de") (Host.Set.add (`Wildcard, Domain_name.(host_exn (of_string_exn "pads.ccc.de"))) (host_set ["pads.ccc.de"]));
  "first hostnames", `Quick, cert_hostnames (cert "../testcertificates/first/first") (host_set ["foo.foobar.com"; "foobar.com"]);
  "CSR your_new_domain hostnames", `Quick, csr_hostnames (csr "your-new-domain") (host_set ["your-new-domain.com" ; "www.your-new-domain.com"]);
  "CSR your_new_domain_raw hostnames", `Quick, csr_hostnames (csr "your-new-domain-raw") (host_set ["your-new-domain.com" ; "www.your-new-domain.com"]);
  "CSR bar.com hostnames", `Quick, csr_hostnames (csr "wild-bar") (Host.Set.add (`Wildcard, Domain_name.(host_exn (of_string_exn "bar.com"))) (host_set ["your-new-domain.com" ; "www.your-new-domain.com"]));
  "CSR foo.com hostnames", `Quick, csr_hostnames (csr "wild-foo-cn") (Host.Set.singleton (`Wildcard, Domain_name.(host_exn (of_string_exn "foo.com"))));
]

let dns_subject_alt_names names =
  let names = General_name.singleton General_name.DNS names in
  Extension.add Extension.Subject_alt_name (false, names) Revoke.leaf_exts

let dns_name_constraints ~permitted ~excluded =
  let subtrees names =
    List.map (fun name -> General_name.B (General_name.DNS, [name]), 0, None) names
  in
  Extension.add Extension.Name_constraints
    (true, (subtrees permitted, subtrees excluded)) (Revoke.ca_exts ())

let name_constraints_union () =
  let now = Ptime_clock.now () in
  let extensions =
    dns_name_constraints ~permitted:["example.com" ; "example.net"] ~excluded:[]
  in
  let ca, capub, capriv = Revoke.selfsigned ~extensions now in
  List.iter (fun name ->
      let example, _, _ =
        Revoke.cert ~name now false capub capriv (Certificate.subject ca)
      in
      match Validation.verify_chain ~host:None ~time ~anchors:[ca] [example] with
      | Ok _ -> ()
      | Error _ -> Alcotest.fail "expected permitted name to validate")
    ["www.example.com" ; "www.example.net"] ;
  let other, _, _ =
    Revoke.cert ~name:"www.other.org" now false capub capriv (Certificate.subject ca)
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
  let ca, capub, capriv = Revoke.selfsigned ~extensions now in
  List.iter (fun (names, allowed) ->
      let extensions = dns_subject_alt_names names in
      let leaf, _, _ =
        Revoke.cert ~name:"unused.invalid" ~extensions now false capub capriv
          (Certificate.subject ca)
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
  let ca, capub, capriv = Revoke.selfsigned ~extensions now in
  List.iter (fun (name, allowed) ->
      let extensions = dns_subject_alt_names [name] in
      let leaf, _, _ =
        Revoke.cert ~extensions now false capub capriv (Certificate.subject ca)
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
  let root, root_pub, root_priv =
    Revoke.selfsigned ~name:"root" ~extensions:root_extensions now
  in
  let intermediate, intermediate_pub, intermediate_priv =
    Revoke.cert ~name:"intermediate" ~extensions:intermediate_extensions now true
      root_pub root_priv (Certificate.subject root)
  in
  List.iter (fun (name, allowed) ->
      let extensions = dns_subject_alt_names [name] in
      let leaf, _, _ =
        Revoke.cert ~extensions now false intermediate_pub intermediate_priv
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
    Extension.add Extension.Name_constraints (true, (permitted, [])) (Revoke.ca_exts ())
  in
  let ca, capub, capriv = Revoke.selfsigned ~extensions now in
  let verify addresses =
    let names = General_name.singleton General_name.IP (List.map Ohex.decode addresses) in
    let extensions = Extension.add Extension.Subject_alt_name (false, names) Revoke.leaf_exts in
    let leaf, _, _ =
      Revoke.cert ~extensions now false capub capriv (Certificate.subject ca)
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
