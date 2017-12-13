(* some revocation scenarios to convince myself *)
open OUnit2

let ca_exts ?pathlen () = [
  (true, (`Basic_constraints (true, pathlen))) ;
  (true, (`Key_usage [ `Key_cert_sign
                     ; `CRL_sign
                     ; `Digital_signature
                     ; `Content_commitment
                     ]))
]

let common_exts subject_pubkey issuer_pubkey =
  let subject_key_id =
    let cs = X509.key_id subject_pubkey in
    (false, `Subject_key_id cs)
  and authority_key_id =
    let cs = X509.key_id issuer_pubkey in
    let x = (Some cs, [], None) in
    (false, `Authority_key_id x)
  in
  [ subject_key_id ; authority_key_id ]

let leaf_exts =
  let ku = (true, (`Key_usage [ `Digital_signature ;
                                `Key_encipherment ]))
  and ext_ku = (true, `Ext_key_usage [ `Server_auth ])
  and bc = (true, `Basic_constraints (false, None))
  in
  [ bc ; ku ; ext_ku ]

let validity now =
  match Ptime.add_span now (Ptime.Span.of_int_s 3600) with
  | Some fut -> (now, fut)
  | None -> invalid_arg "couldn't add 3600 seconds to now"

let key () =
  let key = Nocrypto.Rsa.generate 1024 in
  (`RSA (Nocrypto.Rsa.pub_of_priv key), `RSA key)

let selfsigned ?(name = "test") now =
  let pub, priv = key () in
  let name = [ `CN name ] in
  let req = X509.CA.request name priv in
  let valid_from, valid_until = validity now in
  let cacert = X509.CA.sign req ~valid_from ~valid_until ~extensions:(ca_exts ()) priv name in
  (cacert, pub, priv)

let cert ?serial ?(name = "sub") now ca pubca privca issuer =
  let pub, priv = key () in
  let name = [ `CN name ] in
  let req = X509.CA.request name priv in
  let valid_from, valid_until = validity now in
  let extensions = common_exts pub pubca @ if ca then ca_exts () else leaf_exts in
  let cert = X509.CA.sign req ~valid_from ~valid_until ?serial ~extensions privca issuer in
  (cert, pub, priv)

let verify _ =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let cert, _, _ = cert now false capub capriv (X509.subject ca) in
  match X509.Validation.verify_chain ~anchors:[ca] [cert] with
  | `Ok _ -> ()
  | `Fail _ -> assert_failure ("expected verification to succeed")

let crl _ =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = Z.of_int 42 in
  let issuer = X509.subject ca in
  let cert, _, _ = cert ~serial now false capub capriv issuer in
  let revoked = { X509.CRL.serial ; date = now ; extensions = [] } in
  let crl = X509.CRL.revoke ~issuer ~this_update:now ~extensions:[(false, `CRL_number 1)] [revoked] capriv in
  let revoked = X509.CRL.is_revoked [crl] in
  match X509.Validation.verify_chain ~revoked ~anchors:[ca] [cert] with
  | `Ok _ -> assert_failure ("expected revocation")
  | `Fail (`Chain (`Revoked _)) -> ()
  | `Fail _ -> assert_failure ("expected revoked failure!")

let verify' _ =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = Z.of_int 42 in
  let issuer = X509.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" ~serial now true capub capriv issuer in
  let cert, _pub, _priv = cert now false ipub ipriv (X509.subject ica) in
  match X509.Validation.verify_chain ~anchors:[ca] [cert ; ica] with
  | `Ok _ -> ()
  | `Fail _ -> assert_failure ("expected verification!")

let crl' _ =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = Z.of_int 42 in
  let issuer = X509.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" ~serial now true capub capriv issuer in
  let cert, _pub, _priv = cert now false ipub ipriv (X509.subject ica) in
  let revoked = { X509.CRL.serial ; date = now ; extensions = [] } in
  let crl = X509.CRL.revoke ~issuer ~this_update:now ~extensions:[(false, `CRL_number 1)] [revoked] capriv in
  let revoked = X509.CRL.is_revoked [crl] in
  match X509.Validation.verify_chain ~revoked ~anchors:[ca] [cert ; ica] with
  | `Ok _ -> assert_failure ("expected revocation")
  | `Fail (`Chain (`Revoked _)) -> ()
  | `Fail _ -> assert_failure ("expected revoked failure!")

let crl'leaf _ =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = Z.of_int 42 in
  let ica, ipub, ipriv = cert ~name:"subCA" now true capub capriv (X509.subject ca) in
  let issuer = X509.subject ica in
  let cert, _pub, _priv = cert ~serial now false ipub ipriv issuer in
  let revoked = { X509.CRL.serial ; date = now ; extensions = [] } in
  let crl = X509.CRL.revoke ~issuer ~this_update:now ~extensions:[(false, `CRL_number 1)] [revoked] ipriv in
  let revoked = X509.CRL.is_revoked [crl] in
  match X509.Validation.verify_chain ~revoked ~anchors:[ca] [cert ; ica] with
  | `Ok _ -> assert_failure ("expected revocation")
  | `Fail (`Chain (`Revoked _)) -> ()
  | `Fail _ -> assert_failure ("expected revoked failure!")

let crl'leaf'wrong _ =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = Z.of_int 42 in
  let issuer = X509.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" now true capub capriv issuer in
  let cert, _pub, _priv = cert ~serial now false ipub ipriv (X509.subject ica) in
  let revoked = { X509.CRL.serial ; date = now ; extensions = [] } in
  let crl = X509.CRL.revoke ~issuer ~this_update:now ~extensions:[(false, `CRL_number 1)] [revoked] ipriv in
  let revoked = X509.CRL.is_revoked [crl] in
  match X509.Validation.verify_chain ~revoked ~anchors:[ca] [cert ; ica] with
  | `Ok _ -> ()
  | `Fail _ -> assert_failure ("expected success!")

let verify'' _ =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = Z.of_int 42 in
  let issuer = X509.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" now true capub capriv issuer in
  let cert, _pub, _priv = cert now false ipub ipriv (X509.subject ica) in
  let revoked = { X509.CRL.serial ; date = now ; extensions = [] } in
  let crl = X509.CRL.revoke ~issuer ~this_update:now ~extensions:[(false, `CRL_number 1)] [revoked] capriv in
  let revoked = X509.CRL.is_revoked [crl] in
  match X509.Validation.verify_chain ~revoked ~anchors:[ca] [cert ; ica] with
  | `Ok _ -> ()
  | `Fail _ -> assert_failure ("expected verify to succeed!")

let crl'' _ =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = Z.of_int 42 in
  let issuer = X509.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" ~serial now true capub capriv issuer in
  let cert, _pub, _priv = cert now false ipub ipriv (X509.subject ica) in
  let revoked = { X509.CRL.serial ; date = now ; extensions = [(false, `Reason `Remove_from_CRL)] } in
  let crl = X509.CRL.revoke ~issuer ~this_update:now ~extensions:[(false, `CRL_number 1)] [revoked] capriv in
  let revoked = X509.CRL.is_revoked [crl] in
  match X509.Validation.verify_chain ~revoked ~anchors:[ca] [cert ; ica] with
  | `Ok _ -> ()
  | `Fail _ -> assert_failure ("expected proper verification!")

let revoke_tests = [
  "Verify with a chain works" >:: verify ;
  "Verify with a revoked leaf fails" >:: crl ;
  "Verify with a longer chain works" >:: verify' ;
  "Verify with a revoked intermediate fails" >:: crl' ;
  "Verify with a longer chain works, even if some random serial is revoked" >:: verify'' ;
  "Verify with a revoked `Remove_from_CRL works" >:: crl'' ;
  "Verify with revoked leaf fails" >:: crl'leaf ;
  "Verify with wrongly revoked leaf works" >:: crl'leaf'wrong ;
]
