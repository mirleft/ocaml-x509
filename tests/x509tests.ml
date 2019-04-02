open OUnit2

open X509

let with_loaded_file file ~f =
  let fullpath = "./testcertificates/" ^ file ^ ".pem" in
  let fd = Unix.(openfile fullpath [O_RDONLY] 0) in
  let buf = Unix_cstruct.of_fd fd in
  try let r = f buf in Unix.close fd; r
  with e -> Unix.close fd; raise e

let priv =
  match with_loaded_file "private/cakey"
          ~f:Encoding.Pem.Private_key.of_pem_cstruct1  with
  | `RSA x -> x

let cert name =
  with_loaded_file name ~f:Encoding.Pem.Certificate.of_pem_cstruct1

let invalid_cas = [
  "cacert-basicconstraint-ca-false";
  "cacert-unknown-critical-extension" ;
  "cacert-keyusage-crlsign" ;
  "cacert-ext-usage-timestamping"
]

let cert_public_is_pub cert =
  let pub = Nocrypto.Rsa.pub_of_priv priv in
  ( match public_key cert with
    | `RSA pub' when pub = pub' -> ()
    | _ -> assert_failure "public / private key doesn't match" )

let test_invalid_ca name _ =
  let c = cert name in
  cert_public_is_pub c ;
  assert_equal (List.length (Validation.valid_cas [c])) 0

let invalid_ca_tests =
  List.mapi
    (fun i args -> "invalid CA " ^ string_of_int i >:: test_invalid_ca args)
    invalid_cas

let cacert = cert "cacert"
let cacert_pathlen0 = cert "cacert-pathlen-0"
let cacert_ext = cert "cacert-unknown-extension"
let cacert_ext_ku = cert "cacert-ext-usage"
let cacert_v1 = cert "cacert-v1"

let test_valid_ca c _ =
  cert_public_is_pub c ;
  assert_equal (List.length (Validation.valid_cas [c])) 1

let valid_ca_tests = [
  "valid CA cacert" >:: test_valid_ca cacert ;
  "valid CA cacert_pathlen0" >:: test_valid_ca cacert_pathlen0 ;
  "valid CA cacert_ext" >:: test_valid_ca cacert_ext ;
  "valid CA cacert_v1" >:: test_valid_ca cacert_v1
]

let first_cert name =
  with_loaded_file ("first/" ^ name)
    ~f:Encoding.Pem.Certificate.of_pem_cstruct1

(* ok, now some real certificates *)
let first_certs = [
  ( "first", true,
    [ "foo.foobar.com" ; "foobar.com" ], (* commonName: "bar.foobar.com" *)
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ( "first-basicconstraint-true" , false, [ "ca.foobar.com" ], (* no subjAltName *)
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ( "first-keyusage-and-timestamping", true, [ "ext.foobar.com" ], (* no subjAltName *)
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], Some [`Time_stamping] ) ;
  ( "first-keyusage-any", true, [ "any.foobar.com" ], (* no subjAltName *)
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], Some [`Time_stamping; `Any] ) ;
  ( "first-keyusage-nonrep", true, [ "key.foobar.com" ],  (* no subjAltName *)
    [ `Content_commitment ], None ) ;
  ( "first-unknown-critical-extension", false, (* commonName: "blafasel.com" *)
    [ "foo.foobar.com" ; "foobar.com" ],
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ( "first-unknown-extension", true, [ "foobar.com" ],  (* no subjAltName *)
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
]

let test_valid_ca_cert server chain valid name ca _ =
  match valid, Validation.verify_chain_of_trust ~host:name ~anchors:ca (server :: chain) with
  | false, `Ok _   -> assert_failure "expected to fail, but didn't"
  | false, `Fail _ -> ()
  | true , `Ok _   -> ()
  | true , `Fail c -> assert_failure ("valid certificate " ^ Validation.validation_error_to_string c)

let strict_test_valid_ca_cert server chain valid name ca =
  test_valid_ca_cert server chain valid (`Strict name) ca

let wildcard_test_valid_ca_cert server chain valid name ca =
  test_valid_ca_cert server chain valid (`Wildcard name) ca

let test_cert c usages extusage _ =
  ( if List.for_all (fun u -> Extension.supports_usage c u) usages then
      ()
    else
      assert_failure "key usage is different" ) ;
  ( match extusage with
    | None -> ()
    | Some x when List.for_all (fun u -> Extension.supports_extended_usage c u) x -> ()
    | _ -> assert_failure "extended key usage is broken" )

let first_cert_tests =
  List.mapi
    (fun i (name, _, _, us, eus) ->
     "certificate property testing " ^ string_of_int i >:: test_cert (first_cert name) us eus)
    first_certs

let first_cert_ca_test (ca, x) =
  List.flatten
    (List.map
       (fun (name, valid, cns, _, _) ->
        let c = first_cert name in
        ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: strict_test_valid_ca_cert c [] valid cn [ca])
                  cns @
        List.mapi (fun i cn ->
                   "certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c [] valid cn [ca])
                  cns
       )
    first_certs)

let ca_tests f =
  List.flatten (List.map f
                         [ (cacert, "cacert") ;
                           (cacert_pathlen0, "cacert_pathlen0") ;
                           (cacert_ext, "cacert_ext") ;
                           (cacert_ext_ku, "cacert_ext_ku") ;
                           (cacert_v1, "cacert_v1") ])

let first_wildcard_certs = [
  ( "first-wildcard-subjaltname",
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ( "first-wildcard",
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
]

let first_wildcard_cert_tests =
  List.mapi
    (fun i (name, us, eus) ->
     "wildcard certificate property testing " ^ string_of_int i >:: test_cert (first_cert name) us eus)
    first_wildcard_certs

let first_wildcard_cert_ca_test (ca, x) =
  List.flatten
    (List.map
       (fun (name, _, _) ->
        let c = first_cert name in
        ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        ("certificate verification testing using CA " ^ x ^ " and *.foobar.com "
         >:: strict_test_valid_ca_cert c [] true "*.foobar.com" [ca]) ::
        List.mapi (fun i cn ->
                   "wildcard certificate CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c [] true cn [ca])
                  [ "foo.foobar.com" ; "bar.foobar.com" ; "www.foobar.com" ] @
        List.mapi (fun i cn ->
                   "wildcard certificate CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c [] false cn [ca])
                  [ "foo.foo.foobar.com" ; "bar.fbar.com" ; "foobar.com" ; "com" ; "foobar.com.bla" ]
       )
    first_wildcard_certs)

let intermediate_cas = [
  (true, "cacert") ;
  (true, "cacert-any-ext") ;
  (false, "cacert-ba-false") ;
  (false, "cacert-no-bc") ;
  (false, "cacert-no-keyusage") ;
  (true, "cacert-ku-critical") ;
  (true, "cacert-timestamp") ; (* if we require CAs to have ext_key_usage any, github.com doesn't talk to us *)
  (false, "cacert-unknown") ;
  (false, "cacert-v1")
]

let im_cert name =
  with_loaded_file ("intermediate/" ^ name)
    ~f:Encoding.Pem.Certificate.of_pem_cstruct1

let second_certs = [
  ("second", [ "second.foobar.com" ], true, (* no subjAltName *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ("second-any", [ "second.foobar.com" ], true, (* no subjAltName *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], Some [ `Any ] ) ;
  ("second-subj", [ "foobar.com" ; "foo.foobar.com" ], true, (* commonName: "second.foobar.com" *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ("second-unknown-noncrit", [ "second.foobar.com" ], true, (* no subjAltName *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ("second-nonrepud", [ "second.foobar.com" ], true, (* no subjAltName *)
   [ `Content_commitment ], None ) ;
  ("second-time", [ "second.foobar.com" ], true, (* no subjAltName *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], Some [ `Time_stamping ]) ;
  ("second-subj-wild", [ "foo.foobar.com" ], true, (* commonName: "second.foobar.com" *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ("second-bc-true", [ "second.foobar.com" ], false, (* no subjAltName *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ("second-unknown", [ "second.foobar.com" ], false, (* no subjAltName *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ("second-no-cn", [ ], false, (* no subjAltName *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ("second-subjaltemail", [ ], false, (* email in subjAltName, do not use CN *)
   [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
]

let second_cert name =
  with_loaded_file ("intermediate/second/" ^ name)
    ~f:Encoding.Pem.Certificate.of_pem_cstruct1 

let second_cert_tests =
  List.mapi
    (fun i (name, _, _, us, eus) ->
     "second certificate property testing " ^ string_of_int i >:: test_cert (second_cert name) us eus)
    second_certs

let second_cert_ca_test (cavalid, ca, x) =
  List.flatten
    (List.flatten
       (List.map
          (fun (imvalid, im) ->
           let chain = [im_cert im] in
           List.map
             (fun (name, cns, valid, _, _) ->
              let c = second_cert name in
              ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
              ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
              List.mapi (fun i cn ->
                         "strict certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                         >:: strict_test_valid_ca_cert c chain (cavalid && imvalid && valid) cn [ca])
                        cns @
              List.mapi (fun i cn ->
                         "wildcard certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                         >:: wildcard_test_valid_ca_cert c chain (cavalid && imvalid && valid) cn [ca])
                        cns)
             second_certs)
          intermediate_cas))

let im_ca_tests f =
  List.flatten (List.map f
                         [ (true, cacert, "cacert") ;
                           (true, cacert_ext, "cacert_ext") ;
                           (true, cacert_ext_ku, "cacert_ext_ku") ;
                           (true, cacert_v1, "cacert_v1") ;
                           (false, cacert_pathlen0, "cacert_pathlen0") ])

let second_wildcard_cert_ca_test (cavalid, ca, x) =
  List.flatten
    (List.map
       (fun (imvalid, im) ->
        let chain = [im_cert im] in
        let c = second_cert "second-subj-wild" in
        ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "wildcard certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c chain (cavalid && imvalid) cn [ca])
                  [ "a.foobar.com" ; "foo.foobar.com" ; "foobar.foobar.com" ; "www.foobar.com" ] @
        List.mapi (fun i cn ->
                   "wildcard certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c chain false cn [ca])
                  [ "a.b.foobar.com" ; "f.foobar.com.com" ; "f.f.f." ; "foobar.com.uk" ; "foooo.bar.com" ; "foobar.com" ])
       intermediate_cas)

let second_no_cn_cert_ca_test (_, ca, x) =
  List.flatten
    (List.map
       (fun (_, im) ->
        let chain = [im_cert im] in
        let c = second_cert "second-no-cn" in
        ("verification CA " ^ x ^ " cn blablbalbala" >:: strict_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        ("verification CA " ^ x ^ " cn blablbalbala" >:: wildcard_test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: strict_test_valid_ca_cert c chain false cn [ca])
                  [ "a.foobar.com" ; "foo.foobar.com" ; "foobar.foobar.com" ; "foobar.com" ; "www.foobar.com" ] @
        List.mapi (fun i cn ->
                   "certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i
                   >:: wildcard_test_valid_ca_cert c chain false cn [ca])
                  [ "a.b.foobar.com" ; "f.foobar.com.com" ; "f.f.f." ; "foobar.com.uk" ; "foooo.bar.com" ])
       intermediate_cas)

let invalid_tests =
  let c = second_cert "second" in
  let h = "second.foobar.com" in
  [
    "invalid chain" >:: strict_test_valid_ca_cert c [] false h [cacert] ;
    "broken chain" >:: strict_test_valid_ca_cert c [cacert] false h [cacert] ;
    "no trust anchor" >:: strict_test_valid_ca_cert c [im_cert "cacert"] false h [] ;
    "2chain" >:: strict_test_valid_ca_cert c [im_cert "cacert" ; cacert] true h [cacert] ;
    "3chain" >:: strict_test_valid_ca_cert c [im_cert "cacert" ; cacert ; cacert] true h [cacert] ;
    "chain-order" >:: strict_test_valid_ca_cert c [im_cert "cacert" ; im_cert "cacert" ; cacert] true h [cacert] ;
    "not a CA" >:: (fun _ -> assert_equal (List.length (Validation.valid_cas [im_cert "cacert"])) 0) ;
    "not a CA" >:: (fun _ -> assert_equal (List.length (Validation.valid_cas [c])) 0) ;
  ]

let x509_tests =
  invalid_ca_tests @ valid_ca_tests @
  first_cert_tests @ (ca_tests first_cert_ca_test) @
  first_wildcard_cert_tests @ (ca_tests first_wildcard_cert_ca_test) @
  second_cert_tests @ (im_ca_tests second_cert_ca_test) @ (im_ca_tests second_wildcard_cert_ca_test) @
  (im_ca_tests second_no_cn_cert_ca_test) @
  invalid_tests @
  Regression.regression_tests
