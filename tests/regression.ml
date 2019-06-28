open X509

let cs_mmap file =
  Unix_cstruct.of_fd Unix.(openfile file [O_RDONLY] 0)

let cert file =
  let data = cs_mmap ("./regression/" ^ file ^ ".pem") in
  match Certificate.decode_pem data with
  | Ok cert -> cert
  | Error m -> Alcotest.failf "certificate %s decoding error %a" file pp_decode_error m

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

let regression_tests = [
  "RSA: key too small (jc_jc)", `Quick, test_jc_jc ;
  "jc_ca", `Quick, test_jc_ca ;
  "jfd_ca", `Quick, test_jfd_ca ;
  "jfd_ca'", `Quick, test_jfd_ca'
]
