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

let host str = Domain_name.host_exn (Domain_name.of_string_exn str)

let test_jc_jc () =
  match Validation.verify_chain_of_trust ~host:(`Strict, host "jabber.ccc.de") ~anchors:[jc] [jc] with
  | Error `InvalidChain -> ()
  | Error e -> Alcotest.failf "something went wrong with jc_jc (expected invalid_chain, got %a"
                 Validation.pp_validation_error e
  | Ok _ -> Alcotest.fail "chain validated when it shouldn't"

let test_jc_ca () =
  match Validation.verify_chain_of_trust ~host:(`Strict, host "jabber.ccc.de") ~anchors:[cacert] [jc ; cacert] with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jc_ca"

let telesec = cert "telesec"
let jfd = [ cert "jabber.fu-berlin.de" ; cert "fu-berlin" ; cert "dfn" ]

let test_jfd_ca () =
  match Validation.verify_chain_of_trust ~host:(`Strict, host "jabber.fu-berlin.de") ~anchors:[telesec] (jfd@[telesec]) with
  | Ok _ -> ()
  | _ -> Alcotest.fail "something went wrong with jfd_ca"

let test_jfd_ca' () =
  match Validation.verify_chain_of_trust ~host:(`Strict, host "jabber.fu-berlin.de") ~anchors:[telesec] jfd with
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
  let expected = "O=IZENPE S.A. - CIF A01337260-RMerc.Vitoria-Gasteiz T1055 F62 S8/2.5.4.9=Avda del Mediterraneo Etorbidea 14 - 01010 Vitoria-Gasteiz" in
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

let regression_tests = [
  "RSA: key too small (jc_jc)", `Quick, test_jc_jc ;
  "jc_ca", `Quick, test_jc_ca ;
  "jfd_ca", `Quick, test_jfd_ca ;
  "jfd_ca'", `Quick, test_jfd_ca' ;
  "SAN dir explicit or implicit", `Quick, test_izenpe ;
  "name constraint parsing (DNS: .gr)", `Quick, test_name_constraints ;
  "complex distinguished name", `Quick, test_distinguished_name ;
]
