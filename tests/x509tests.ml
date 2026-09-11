open X509

let host name = Domain_name.host_exn (Domain_name.of_string_exn name)

let now = Ptime_clock.now ()

let an_hour_ago = Option.get (Ptime.sub_span now (Ptime.Span.of_int_s 3600))

let an_hour_ahead = Option.get (Ptime.add_span now (Ptime.Span.of_int_s 3600))

let time () = Some now

let ca_key =
  Result.get_ok
    (X509.Private_key.decode_pem
       {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEFPEg8sz2fIPOnLVeW3L5iZG3D95r+4dbiS3Uhtiwnc
-----END PRIVATE KEY-----|})

let ca_name =
  [ Distinguished_name.(Relative_distinguished_name.singleton (CN (Common_name.v "cacert"))) ]

let validity now =
  Option.get (Ptime.sub_span now (Ptime.Span.of_int_s 10)),
  Option.get (Ptime.add_span now (Ptime.Span.of_int_s 10))

let ca_exts ?pathlen () =
  let ku =
    [ `Key_cert_sign ; `CRL_sign ; `Digital_signature ; `Content_commitment ]
  in
  Extension.(add Basic_constraints (true, (true, pathlen))
               (singleton Key_usage (true, ku)))

let selfsigned ?(priv = ca_key) ?(name = ca_name) ?(now = now) extensions =
  match Signing_request.create name priv with
  | Error _ -> assert false
  | Ok req ->
    let valid_from, valid_until = validity now in
    match X509.Signing_request.sign req ~valid_from ~valid_until ~extensions ~serial:"hello" priv name with
    | Ok cacert -> cacert
    | Error _ -> assert false

let signed ?(now = now) ?(ca_key = ca_key) ?(ca_name = ca_name) priv name extensions =
  let name = [ Distinguished_name.(Relative_distinguished_name.singleton (CN (Common_name.v name))) ] in
  match Signing_request.create name priv with
  | Error _ -> assert false
  | Ok req ->
    let valid_from, valid_until = validity now in
    Result.get_ok (X509.Signing_request.sign req ~valid_from ~valid_until ~extensions ~serial:"hello" ~subject:name ca_key ca_name)

let signed_name ?(ca_key = ca_key) ?(ca_name = ca_name) priv name extensions =
  match Signing_request.create name priv with
  | Error _ -> assert false
  | Ok req ->
    let valid_from, valid_until = validity now in
    Result.get_ok (X509.Signing_request.sign req ~valid_from ~valid_until ~extensions ~serial:"hello" ~subject:name ca_key ca_name)

let invalid_cas =
  let ca_false =
    let ca_exts =
      let ku = [ `Key_cert_sign ; `CRL_sign ] in
      Extension.(add Basic_constraints (true, (false, None))
                   (singleton Key_usage (true, ku)))
    in
    selfsigned ca_exts
  and unknown_critical_ext =
    let ca_exts =
      let ku = [ `Key_cert_sign ; `CRL_sign ] in
      let unknown = Option.get (Asn.OID.of_string "1.2.3.4") in
      Extension.(add (Unsupported unknown) (true, "Some random data")
                   (add Basic_constraints (true, (true, Some 100))
                      (singleton Key_usage (true, ku))))
    in
    selfsigned ca_exts
  and keyusage_crlsign =
    let ca_exts =
      let ku = [ `CRL_sign ] in
      Extension.(add Basic_constraints (true, (true, None))
                   (singleton Key_usage (true, ku)))
    in
    selfsigned ca_exts
  and ext_keyusage_timestamping =
    let ca_exts =
      let ku = [ `Key_cert_sign ; `CRL_sign ] in
      let eku = [ `Time_stamping ] in
      Extension.(add Ext_key_usage (true, eku)
                   (add Basic_constraints (true, (true, None))
                      (singleton Key_usage (true, ku))))
    in
    selfsigned ca_exts
  and expired =
    let ca_exts =
      let ku = [ `Key_cert_sign ; `CRL_sign ] in
      Extension.(add Basic_constraints (true, (false, None))
                   (singleton Key_usage (true, ku)))
    in
    selfsigned ~now:an_hour_ago ca_exts
  and not_yet_valid =
    let ca_exts =
      let ku = [ `Key_cert_sign ; `CRL_sign ] in
      Extension.(add Basic_constraints (true, (false, None))
                   (singleton Key_usage (true, ku)))
    in
    selfsigned ~now:an_hour_ahead ca_exts
  in
  [ ca_false ; unknown_critical_ext ; keyusage_crlsign ; ext_keyusage_timestamping ; expired ; not_yet_valid ]

let test_invalid_ca c () =
  Alcotest.(check int "CA list is empty" 0
              (List.length (Validation.valid_cas [c])))

let invalid_ca_tests =
  List.mapi
    (fun i ca -> "invalid CA " ^ string_of_int i, `Quick, test_invalid_ca ca)
    invalid_cas

let cacert =
  let ca_exts =
    let ku = [ `Key_cert_sign ; `CRL_sign ] in
    Extension.(add Basic_constraints (true, (true, Some 100))
                 (singleton Key_usage (true, ku)))
  in
  selfsigned ca_exts

let cacert_pathlen0 =
  let ca_exts =
    let ku = [ `Key_cert_sign ; `CRL_sign ] in
    Extension.(add Basic_constraints (true, (true, Some 0))
                 (singleton Key_usage (true, ku)))
  in
  selfsigned ca_exts

let cacert_ext =
  let ca_exts =
    let ku = [ `Key_cert_sign ; `CRL_sign ] in
    let unknown = Option.get (Asn.OID.of_string "1.2.3.4") in
    Extension.(add (Unsupported unknown) (false, "Some random data")
                 (add Basic_constraints (true, (true, None))
                    (singleton Key_usage (true, ku))))
  in
  selfsigned ca_exts

let cacert_ext_ku =
  let ca_exts =
    let ku = [ `Key_cert_sign ; `CRL_sign ] in
    let eku = [ `Any ] in
    Extension.(add Ext_key_usage (true, eku)
                 (add Basic_constraints (true, (true, None))
                    (singleton Key_usage (true, ku))))
  in
  selfsigned ca_exts

let test_valid_ca c () =
  Alcotest.(check int "CA is valid" 1
              (List.length (Validation.valid_cas [c])))

let valid_ca_tests = [
  "valid CA cacert", `Quick, test_valid_ca cacert;
  "valid CA cacert_pathlen0", `Quick, test_valid_ca cacert_pathlen0;
  "valid CA cacert_ext", `Quick, test_valid_ca cacert_ext;
]

let exts ?ku ?eku ?names ?more () =
  let ext = Extension.(singleton Basic_constraints (false, (false, None))) in
  let ext =
    match ku with
    | None -> ext
    | Some ku -> Extension.(add Key_usage (false, ku) ext)
  in
  let ext =
    match eku with
    | None -> ext
    | Some eku -> Extension.(add Ext_key_usage (false, eku) ext)
  in
  let ext =
    match names with
    | None -> ext
    | Some names ->
      let san = General_name.(singleton DNS names) in
      Extension.(add Subject_alt_name (false, san) ext)
  in
  match more with
  | None -> ext
  | Some (Extension.B (k, v)) -> Extension.add k v ext

let first_priv =
  Result.get_ok
    (X509.Private_key.decode_pem
       {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBCBOR2Olzdb/2ddbpWD3z+n53Qzn7xWcJLkBAmZHNLV
-----END PRIVATE KEY-----|})

(* ok, now some real certificates *)
let first_certs =
  let sign name exts = signed first_priv name exts in
  [
    ( "first", true,
      exts
        ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
        ~names:[ "foo.foobar.com" ; "foobar.com" ] () |>
      sign "bar.foobar.com",
      [ "foo.foobar.com" ; "foobar.com" ],
      [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
      None );
    ( "first-no-san", true,
      exts
        ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ] () |>
      sign "no-san.foobar.com",
      [ "no-san.foobar.com" ],
      [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
      None );
    ( "first-basicconstraint-true", false,
      exts
        ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
        ~more:(Extension.B (Basic_constraints, (false, (true, None))))
        ~names:[ "ca.foobar.com" ] () |>
      sign "ca.foobar.com",
      [ "ca.foobar.com" ],
      [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
      None );
    ( "first-keyusage-and-timestamping", true,
      exts
        ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
        ~names:[ "ext.foobar.com" ]
        ~eku:[`Time_stamping] () |>
      sign "ext.foobar.com",
      [ "ext.foobar.com" ],
      [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
      Some [ `Time_stamping ] );
    ( "first-keyusage-any", true,
      exts
        ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
        ~names:[ "any.foobar.com" ]
        ~eku:[`Time_stamping ; `Any] () |>
      sign "any.foobar.com",
      [ "any.foobar.com" ],
      [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
      Some [ `Time_stamping ; `Any ] );
    ( "first-keyusage-nonrep", true,
      exts
        ~ku:[ `Content_commitment ]
        ~names:[ "key.foobar.com" ] () |>
      sign "key.foobar.com",
      [ "key.foobar.com" ],
      [ `Content_commitment ],
      None );
    ( "first-unknown-critical-extension", false,
      exts
        ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
        ~names:[ "foo.foobar.com" ; "foobar.com" ]
        ~more:(Extension.B (Unsupported (Option.get (Asn.OID.of_string "1.2.3.4")), (true, "Some random data"))) () |>
      sign "blafasel.com",
      [ "foo.foobar.com" ; "foobar.com" ],
      [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
      None );
    ( "first-unknown-extension", true,
      exts
        ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
        ~names:[ "foobar.com" ]
        ~more:(Extension.B (Unsupported (Option.get (Asn.OID.of_string "1.2.3.4")), (false, "Some random data")))
        () |>
      sign "blafasel.com",
      [ "foobar.com" ],
      [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
      None );
    ( "first-expired", false,
      exts
        ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
        ~names:[ "foobar.com" ]
        () |>
      signed ~now:an_hour_ago first_priv "foobar.com",
      [ "foobar.com" ],
      [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
      None );
    ( "first-not-yet-valid", false,
      exts
        ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
        ~names:[ "foobar.com" ]
        () |>
      signed ~now:an_hour_ahead first_priv "foobar.com",
      [ "foobar.com" ],
      [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
      None );
  ]

let allowed_hashes = [ `MD5 ; `SHA1 ; `SHA224 ; `SHA256 ; `SHA384 ; `SHA512 ]

let test_valid_ca_cert ?(allowed_hashes = allowed_hashes) server chain valid name ca () =
  let anchors = ca
  and host = Some (host name)
  and full_chain = server :: chain
  in
  match valid, Validation.verify_chain_of_trust ~time ~allowed_hashes ~host ~anchors full_chain with
  | false, Ok _   -> Alcotest.fail "expected to fail, but didn't"
  | false, Error _ -> ()
  | true , Ok _   -> ()
  | true , Error c -> Alcotest.failf "valid certificate %a" Validation.pp_validation_error c

let test_cert c usages extusage () =
  let ku, eku =
    let exts = Certificate.extensions c in
    let ku = match Extension.(find Key_usage exts) with
      | None -> []
      | Some (_crit, ku) -> ku
    and eku = match Extension.(find Ext_key_usage exts) with
      | None -> []
      | Some (_crit, eku) -> eku
    in
    ku, eku
  in
  ( if List.for_all (fun u -> List.mem u ku) usages then
      ()
    else
      Alcotest.fail "key usage is different" ) ;
  ( match extusage with
    | None -> ()
    | Some x when List.for_all (fun u -> List.mem u eku) x -> ()
    | _ -> Alcotest.fail "extended key usage is broken" )

let first_cert_tests =
  List.mapi
    (fun i (_, _, cert, _, us, eus) ->
       "certificate property testing " ^ string_of_int i, `Quick,
       test_cert cert us eus)
    first_certs

let first_cert_ca_test (ca, x) =
  List.flatten
    (List.map
       (fun (_, valid, c, cns, _, _) ->
        ("verification CA " ^ x ^ " cn blablbalbala", `Quick, test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i,
                   `Quick, test_valid_ca_cert c [] valid cn [ca])
                  cns)
    first_certs)

let ca_tests f =
  List.flatten (List.map f
                         [ (cacert, "cacert") ;
                           (cacert_pathlen0, "cacert_pathlen0") ;
                           (cacert_ext, "cacert_ext") ;
                           (cacert_ext_ku, "cacert_ext_ku") ])

let first_wildcard_certs = [
  ( "first-wildcard-subjaltname",
    exts
      ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
      ~names:[ "*.foobar.com" ] () |>
    signed first_priv "wildcard.foobar.com",
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
  ( "first-wildcard",
    exts
      ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ] () |>
    signed first_priv "*.foobar.com",
    [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
]

let first_wildcard_cert_tests =
  List.mapi
    (fun i (_name, cert, us, eus) ->
     "wildcard certificate property testing " ^ string_of_int i, `Quick, test_cert cert us eus)
    first_wildcard_certs

let first_wildcard_cert_ca_test (ca, x) =
  List.flatten
    (List.map
       (fun (_name, c, _, _) ->
        ("verification CA " ^ x ^ " cn blablbalbala", `Quick, test_valid_ca_cert c [] false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "wildcard certificate CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i,
                   `Quick, test_valid_ca_cert c [] true cn [ca])
                  [ "foo.foobar.com" ; "bar.foobar.com" ; "www.foobar.com" ] @
        List.mapi (fun i cn ->
                   "wildcard certificate CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i,
                   `Quick, test_valid_ca_cert c [] false cn [ca])
                  [ "foo.foo.foobar.com" ; "bar.fbar.com" ; "foobar.com" ; "com" ; "foobar.com.bla" ]
       )
    first_wildcard_certs)

let im_name =   [ Distinguished_name.(Relative_distinguished_name.singleton (CN (Common_name.v "signing CA"))) ]

let im_priv =
    Result.get_ok
      (Private_key.decode_pem {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICXhHhrw5qaoj8EbY37Hzi5ni6nXa2kIGNinCvjT4rhM
-----END PRIVATE KEY-----|})

let intermediate_cas =
  let name = "signing CA" in
  let sign exts = signed im_priv name exts in
  [
    (true, sign Extension.(add Basic_constraints (true, (true, None)) (singleton Key_usage (false, [`Key_cert_sign; `CRL_sign])))) ;
    (true, sign Extension.(add Ext_key_usage (false, [`Any]) (add Basic_constraints (true, (true, None)) (singleton Key_usage (false, [`Key_cert_sign ; `CRL_sign]))))) ;
    (false, sign Extension.(add Basic_constraints (true, (false, None)) (singleton Key_usage (false, [`Key_cert_sign; `CRL_sign])))) ;
    (false, sign Extension.(singleton Key_usage (false, [`Key_cert_sign; `CRL_sign]))) ;
    (false, sign Extension.(singleton Basic_constraints (true, (true, None)))) ;
    (true, sign Extension.(add Basic_constraints (true, (true, None)) (singleton Key_usage (true, [`Key_cert_sign; `CRL_sign])))) ;
    (false, sign Extension.(add Basic_constraints (true, (true, None)) (add Key_usage (false, [`Key_cert_sign; `CRL_sign]) (singleton Ext_key_usage (false, [`Time_stamping]))))) ;
    (false, sign Extension.(add Basic_constraints (true, (true, None)) (add Key_usage (false, [`Key_cert_sign; `CRL_sign]) (singleton (Unsupported (Option.get (Asn.OID.of_string "1.2.3.4"))) (true, "Some random data")))));
    (false, signed ~now:an_hour_ago im_priv name Extension.(add Basic_constraints (true, (true, None)) (singleton Key_usage (false, [`Key_cert_sign; `CRL_sign])))) ;
    (false, signed ~now:an_hour_ahead im_priv name Extension.(add Basic_constraints (true, (true, None)) (singleton Key_usage (false, [`Key_cert_sign; `CRL_sign])))) ;
]

let second_certs =
  let second_priv =
    Result.get_ok
      (X509.Private_key.decode_pem
         {|-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID1tIgjIqM2gFu+7kNfu+8TW+5Vug0nAHtuyMgPkKnT+
-----END PRIVATE KEY-----|})
  in
  let sign name exts = signed ~ca_key:im_priv ~ca_name:im_name second_priv name exts in
  let other_name = [ Distinguished_name.(Relative_distinguished_name.singleton (O (Organization_name.v "tada"))) ] in
  [
    ("second", true,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       ~names:[ "second.foobar.com" ] ()
     |> sign "second.foobar.com",
     [ "second.foobar.com" ],
     [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
     None ) ;
    ("second-no-san", true,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       () |> sign "second.foobar.com",
     [ "second.foobar.com" ],
     [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
     None ) ;
    ("second-any", true,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       ~names:[ "second.foobar.com" ]
       ~eku:[ `Any ] () |>
     sign "second.foobar.com",
     [ "second.foobar.com" ],
     [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
     Some [ `Any ] ) ;
    ("second-subj", true,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       ~names:[ "foobar.com" ; "foo.foobar.com" ] () |>
     sign "second.foobar.com",
     [ "foobar.com" ; "foo.foobar.com" ],
     [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
     None ) ;
    ("second-unknown-noncrit", true,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       ~names:[ "second.foobar.com" ]
       ~more:(Extension.B (Unsupported (Option.get (Asn.OID.of_string "1.2.3.4")), (false, "Some random data")))
       () |>
     sign "second.foobar.com",
     [ "second.foobar.com" ],
     [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
    ("second-nonrepud", true,
     exts ~ku:[ `Content_commitment ] ~names:[ "second.foobar.com" ] () |>
     sign "second.foobar.com",
     [ "second.foobar.com" ], [ `Content_commitment ], None ) ;
    ("second-time", true,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       ~eku:[ `Time_stamping ]
       ~names:[ "second.foobar.com" ]
       () |> sign "second.foobar.com",
       [ "second.foobar.com" ],
     [ `Digital_signature ; `Content_commitment ; `Key_encipherment ],
     Some [ `Time_stamping ]) ;
    ("second-subj-wild", true,
     exts ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       ~names:[ "*.foobar.com" ; "foo.foobar.com" ]
       () |> sign "second.foobar.com",
     [ "foo.foobar.com" ; "bar.foobar.com" ; "baz.foobar.com" ],
     [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
    ("second-bc-true", false,
     exts ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       ~names:[ "second.foobar.com" ]
       ~more:(Extension.B (Basic_constraints, (true, (true, None)))) () |>
     sign "second.foobar.com",
     [ "second.foobar.com" ],
     [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
    ("second-unknown", false,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       ~names:[ "second.foobar.com" ]
       ~more:(Extension.B (Unsupported (Option.get (Asn.OID.of_string "1.2.3.4")), (true, "Some random data")))
       () |>
     sign "second.foobar.com",
     [ "second.foobar.com" ],
     [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
    ("second-no-cn", false,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       () |>
     signed_name ~ca_key:im_priv ~ca_name:im_name second_priv other_name,
     [], [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
    ("second-subjaltemail", false,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       ~more:(Extension.B (Subject_alt_name, (false, General_name.(singleton Rfc_822 [ "foobar.com" ]))))
       () |>
     sign "second.foobar.com",
     [], [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
    ("second-expired", false,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       () |>
     signed ~now:an_hour_ago ~ca_key:im_priv ~ca_name:im_name second_priv "second.foobar.com",
     [], [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
    ("second-not-yet-valid", false,
     exts
       ~ku:[ `Digital_signature ; `Content_commitment ; `Key_encipherment ]
       () |>
     signed ~now:an_hour_ahead ~ca_key:im_priv ~ca_name:im_name second_priv "second.foobar.com",
     [], [ `Digital_signature ; `Content_commitment ; `Key_encipherment ], None ) ;
]

let second_cert_tests =
  List.mapi
    (fun i (_name, _, cert, _, us, eus) ->
     "second certificate property testing " ^ string_of_int i, `Quick, test_cert cert us eus)
    second_certs

let second_cert_ca_test (cavalid, ca, x) =
  List.flatten
    (List.flatten
       (List.map
          (fun (imvalid, im_cert) ->
           let chain = [im_cert] in
           List.map
             (fun (_name, valid, c, cns, _, _) ->
              ("verification CA " ^ x ^ " cn blablbalbala", `Quick, test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
              List.mapi (fun i cn ->
                         "strict certificate verification testing using CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i,
                         `Quick, test_valid_ca_cert c chain (cavalid && imvalid && valid) cn [ca])
                        cns)
             second_certs)
          intermediate_cas))

let im_ca_tests f =
  List.flatten (List.map f
                         [ (true, cacert, "cacert") ;
                           (true, cacert_ext, "cacert_ext") ;
                           (true, cacert_ext_ku, "cacert_ext_ku") ;
                           (false, cacert_pathlen0, "cacert_pathlen0") ])

let second_wildcard_cert_ca_test (cavalid, ca, x) =
  List.flatten
    (List.map
       (fun (imvalid, im_cert) ->
        let chain = [im_cert] in
        let c = List.find (fun (name, _, _, _, _, _) -> String.equal name "second-subj-wild") second_certs in
        let _, _, c, _, _, _ = c in
        ("verification CA " ^ x ^ " cn blablbalbala", `Quick, test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "wildcard certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i,
                   `Quick, test_valid_ca_cert c chain (cavalid && imvalid) cn [ca])
                  [ "a.foobar.com" ; "foo.foobar.com" ; "foobar.foobar.com" ; "www.foobar.com" ] @
        List.mapi (fun i cn ->
                   "wildcard certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i,
                   `Quick, test_valid_ca_cert c chain false cn [ca])
                  [ "a.b.foobar.com" ; "f.foobar.com.com" ; "f.f.f." ; "foobar.com.uk" ; "foooo.bar.com" ; "foobar.com" ])
       intermediate_cas)

let second_no_cn_cert_ca_test (_, ca, x) =
  List.flatten
    (List.map
       (fun (_, im_cert) ->
        let chain = [im_cert] in
        let c = List.find (fun (name, _, _, _, _, _) -> String.equal name "second-no-cn") second_certs in
        let _, _, c, _, _, _ = c in
        ("verification CA " ^ x ^ " cn blablbalbala", `Quick, test_valid_ca_cert c chain false "blablabalbal" [ca]) ::
        List.mapi (fun i cn ->
                   "certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i,
                   `Quick, test_valid_ca_cert c chain false cn [ca])
                  [ "a.foobar.com" ; "foo.foobar.com" ; "foobar.foobar.com" ; "foobar.com" ; "www.foobar.com" ] @
        List.mapi (fun i cn ->
                   "certificate verification CA " ^ x ^ " and CN " ^ cn ^ " " ^ string_of_int i,
                   `Quick, test_valid_ca_cert c chain false cn [ca])
                  [ "a.b.foobar.com" ; "f.foobar.com.com" ; "f.f.f." ; "foobar.com.uk" ; "foooo.bar.com" ])
       intermediate_cas)

let invalid_tests =
  let c = List.hd second_certs in
  let _, _, c, _, _, _ = c in
  let h = "second.foobar.com" in
  let allowed_hashes = [ `MD5 ] in
  [
    "invalid chain", `Quick, test_valid_ca_cert c [] false h [cacert] ;
    "broken chain", `Quick, test_valid_ca_cert c [cacert] false h [cacert] ;
    "no trust anchor", `Quick, test_valid_ca_cert c [snd (List.hd intermediate_cas)] false h [] ;
    "2chain invalid", `Quick, test_valid_ca_cert ~allowed_hashes c [snd (List.hd intermediate_cas) ; cacert] false h [cacert] ;
    "2chain valid", `Quick, test_valid_ca_cert c [snd (List.hd intermediate_cas) ; cacert] true h [cacert] ;
    "3chain invalid", `Quick, test_valid_ca_cert ~allowed_hashes c [snd (List.hd intermediate_cas) ; cacert ; cacert] false h [cacert] ;
    "3chain valid", `Quick, test_valid_ca_cert c [snd (List.hd intermediate_cas) ; cacert ; cacert] true h [cacert] ;
    "chain-order invalid", `Quick, test_valid_ca_cert ~allowed_hashes c [snd (List.hd intermediate_cas) ; snd (List.hd intermediate_cas) ; cacert] false h [cacert] ;
    "chain-order valid", `Quick, test_valid_ca_cert c [snd (List.hd intermediate_cas) ; snd (List.hd intermediate_cas) ; cacert] true h [cacert] ;
    "not a CA", `Quick, (fun _ -> Alcotest.(check int "is not a CA" 0
                                              (List.length (Validation.valid_cas [snd (List.hd intermediate_cas)])))) ;
    "not a CA", `Quick, (fun _ -> Alcotest.(check int "is also not a CA" 0
                                              (List.length (Validation.valid_cas [c])))) ;
  ]

let x509_tests = [
  "Invalid CA", invalid_ca_tests ;
  "Valid CA", valid_ca_tests ;
  "Certificate", first_cert_tests ;
  "CA tests with certificate", ca_tests first_cert_ca_test ;
  "Wildcard certificate", first_wildcard_cert_tests ;
  "CA tests with wildcard certificate", ca_tests first_wildcard_cert_ca_test ;
  "Second certificate test", second_cert_tests ;
  "Intermediate CA with second certificate", im_ca_tests second_cert_ca_test ;
  "Intermediate CA with CA and second", im_ca_tests second_wildcard_cert_ca_test ;
  "Intermediate CA with second no common name", im_ca_tests second_no_cn_cert_ca_test ;
  "Tests with invalid data", invalid_tests
]
