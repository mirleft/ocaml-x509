open X509

let cs_mmap file =
  Unix_cstruct.of_fd Unix.(openfile file [O_RDONLY] 0)

let cert file =
  let data = cs_mmap ("./regression/" ^ file ^ ".pem") in
  match Certificate.decode_pem data with
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
  match Validation.verify_chain_of_trust ~hash_whitelist:[`SHA1] ~host:(host "jabber.ccc.de") ~time ~anchors:[cacert] [jc ; cacert] with
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

let regression_tests = [
  "RSA: key too small (jc_jc)", `Quick, test_jc_jc ;
  "jc_ca", `Quick, test_jc_ca_fail ;
  "jc_ca", `Quick, test_jc_ca_all_hashes ;
  "jfd_ca", `Quick, test_jfd_ca ;
  "jfd_ca'", `Quick, test_jfd_ca' ;
  "SAN dir explicit or implicit", `Quick, test_izenpe ;
  "name constraint parsing (DNS: .gr)", `Quick, test_name_constraints ;
  "complex distinguished name", `Quick, test_distinguished_name ;
  "distinguished name pp", `Quick, test_distinguished_name_pp ;
  "algorithm without null", `Quick, test_yubico ;
]

let host_set_test =
  let module M = struct
    type t = Host.Set.t
    let pp ppf hs =
      let pp_one ppf (typ, name) =
        Fmt.pf ppf "%s%a"
          (match typ with `Strict -> "" | `Wildcard -> "*.")
          Domain_name.pp name
      in
      Fmt.(list ~sep:(unit ", ") pp_one) ppf (Host.Set.elements hs)
    let equal = Host.Set.equal
  end in (module M: Alcotest.TESTABLE with type t = M.t)

let cert_hostnames cert names () =
  Alcotest.check host_set_test __LOC__ (Certificate.hostnames cert) names

let csr file =
  let data = cs_mmap ("./csr/" ^ file ^ ".pem") in
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
