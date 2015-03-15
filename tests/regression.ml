open OUnit2

open X509

let cs_mmap file =
  Unix_cstruct.of_fd Unix.(openfile file [O_RDONLY] 0)

let cert file =
  Parser.Cert.of_pem_cstruct1 (cs_mmap ("./tests/regression/" ^ file ^ ".pem"))

let jc = cert "jabber.ccc.de"
let cacert = cert "cacert"

let test_jc_jc _ =
  match Certificate.verify_chain_of_trust ~host:(`Strict "jabber.ccc.de") ~anchors:[jc] [jc] with
  | `Fail Certificate.NoTrustAnchor -> ()
  | _                   -> assert_failure ("something went wrong with jc_jc")

let test_jc_ca _ =
  match Certificate.verify_chain_of_trust ~host:(`Strict "jabber.ccc.de") ~anchors:[cacert] [jc ; cacert] with
  | `Ok _ -> ()
  | _     -> assert_failure ("something went wrong with jc_ca")


let regression_tests = [
  "RSA: key too small (jc_jc)" >:: test_jc_jc ;
  "jc_ca" >:: test_jc_ca
]
