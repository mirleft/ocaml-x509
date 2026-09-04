open X509

let time () = None

(* some revocation scenarios to convince myself *)
let ca_exts ?pathlen () =
  let ku =
    [ `Key_cert_sign ; `CRL_sign ; `Digital_signature ; `Content_commitment ]
  in
  Extension.(add Basic_constraints (true, (true, pathlen))
               (singleton Key_usage (true, ku)))

let key_ids exts subject_pubkey issuer_pubkey =
  let subject_key_id =
    false, Public_key.id subject_pubkey
  and authority_key_id =
    let cs = Public_key.id issuer_pubkey in
    false, (Some cs, General_name.empty, None)
  in
  Extension.(add Subject_key_id subject_key_id
               (add Authority_key_id authority_key_id exts))

let leaf_exts =
  Extension.(add Key_usage (true, [ `Digital_signature ; `Key_encipherment ])
               (add Ext_key_usage (true, [ `Server_auth ])
                  (singleton Basic_constraints (true, (false, None)))))

let validity now =
  match Ptime.add_span now (Ptime.Span.of_int_s 3600) with
  | Some fut -> (now, fut)
  | None -> invalid_arg "couldn't add 3600 seconds to now"

let key () =
  let key = Mirage_crypto_pk.Rsa.generate ~bits:1024 () in
  (`RSA (Mirage_crypto_pk.Rsa.pub_of_priv key), `RSA key)

let selfsigned ?(name = "test") ?(extensions = ca_exts ()) now =
  let pub, priv = key () in
  let name = [ Distinguished_name.(Relative_distinguished_name.singleton (CN name)) ] in
  match Signing_request.create name priv with
  | Error _ -> assert false
  | Ok req ->
    let valid_from, valid_until = validity now in
    match X509.Signing_request.sign req ~valid_from ~valid_until ~extensions priv name with
    | Ok cacert -> (cacert, pub, priv)
    | Error _ -> assert false

let cert ?serial ?(name = "sub") ?extensions now ca pubca privca issuer =
  let pub, priv = key () in
  let name = [ Distinguished_name.(Relative_distinguished_name.singleton (CN name)) ] in
  match Signing_request.create name priv with
  | Error _ -> assert false
  | Ok req ->
    let valid_from, valid_until = validity now in
    let extensions = match extensions with
      | Some extensions -> extensions
      | None -> if ca then ca_exts () else leaf_exts
    in
    let extensions = key_ids extensions pub pubca in
    match X509.Signing_request.sign req ~valid_from ~valid_until ?serial ~extensions privca issuer with
    | Ok cert -> (cert, pub, priv)
    | Error _ -> assert false

let verify () =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let cert, _, _ = cert now false capub capriv (Certificate.subject ca) in
  match Validation.verify_chain ~host:None ~time ~anchors:[ca] [cert] with
  | Ok _ -> ()
  | Error _ -> Alcotest.fail "expected verification to succeed"

let dns_name_constraints ~permitted ~excluded =
  let subtrees names =
    List.map (fun name -> General_name.B (General_name.DNS, [name]), 0, None) names
  in
  Extension.add Extension.Name_constraints
    (true, (subtrees permitted, subtrees excluded)) (ca_exts ())

let dns_subject_alt_names names =
  let names = General_name.singleton General_name.DNS names in
  Extension.add Extension.Subject_alt_name (false, names) leaf_exts

let name_constraints_union () =
  let now = Ptime_clock.now () in
  let extensions =
    dns_name_constraints ~permitted:["example.com" ; "example.net"] ~excluded:[]
  in
  let ca, capub, capriv = selfsigned ~extensions now in
  List.iter (fun name ->
      let example, _, _ =
        cert ~name now false capub capriv (Certificate.subject ca)
      in
      match Validation.verify_chain ~host:None ~time ~anchors:[ca] [example] with
      | Ok _ -> ()
      | Error _ -> Alcotest.fail "expected permitted name to validate")
    ["www.example.com" ; "www.example.net"] ;
  let other, _, _ =
    cert ~name:"www.other.org" now false capub capriv (Certificate.subject ca)
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
  let ca, capub, capriv = selfsigned ~extensions now in
  List.iter (fun (names, allowed) ->
      let extensions = dns_subject_alt_names names in
      let leaf, _, _ =
        cert ~name:"unused.invalid" ~extensions now false capub capriv
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
  let ca, capub, capriv = selfsigned ~extensions now in
  List.iter (fun (name, allowed) ->
      let extensions = dns_subject_alt_names [name] in
      let leaf, _, _ =
        cert ~extensions now false capub capriv (Certificate.subject ca)
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
    selfsigned ~name:"root" ~extensions:root_extensions now
  in
  let intermediate, intermediate_pub, intermediate_priv =
    cert ~name:"intermediate" ~extensions:intermediate_extensions now true
      root_pub root_priv (Certificate.subject root)
  in
  List.iter (fun (name, allowed) ->
      let extensions = dns_subject_alt_names [name] in
      let leaf, _, _ =
        cert ~extensions now false intermediate_pub intermediate_priv
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
    Extension.add Extension.Name_constraints (true, (permitted, [])) (ca_exts ())
  in
  let ca, capub, capriv = selfsigned ~extensions now in
  let verify addresses =
    let names = General_name.singleton General_name.IP (List.map Ohex.decode addresses) in
    let extensions = Extension.add Extension.Subject_alt_name (false, names) leaf_exts in
    let leaf, _, _ =
      cert ~extensions now false capub capriv (Certificate.subject ca)
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

let crl () =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let cert, _, _ = cert ~serial now false capub capriv issuer in
  let revoked = { CRL.serial ; date = now ; extensions = Extension.empty } in
  let extensions = Extension.(singleton CRL_number (false, 1)) in
  match CRL.revoke ~issuer ~this_update:now ~extensions [revoked] capriv with
  | Error _ -> Alcotest.fail "couldn't revoke"
  | Ok crl ->
    let revoked = CRL.is_revoked [crl] ?allowed_hashes:None in
    match Validation.verify_chain ~host:None ~time ~revoked ~anchors:[ca] [cert] with
    | Ok _ -> Alcotest.fail "expected revocation"
    | Error (`Revoked _) -> ()
    | Error _ -> Alcotest.fail "expected revoked failure!"

let verify' () =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" ~serial now true capub capriv issuer in
  let cert, _pub, _priv = cert now false ipub ipriv (Certificate.subject ica) in
  match Validation.verify_chain ~host:None ~time ~anchors:[ca] [cert ; ica] with
  | Ok _ -> ()
  | Error _ -> Alcotest.fail "expected verification!"

let crl' () =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" ~serial now true capub capriv issuer in
  let cert, _pub, _priv = cert now false ipub ipriv (Certificate.subject ica) in
  let revoked = { CRL.serial ; date = now ; extensions = Extension.empty } in
  let extensions = Extension.(singleton CRL_number (false, 1)) in
  match CRL.revoke ~issuer ~this_update:now ~extensions [revoked] capriv with
  | Error _ -> Alcotest.fail "couldn't revoke"
  | Ok crl ->
    let revoked = CRL.is_revoked [crl] ?allowed_hashes:None in
    match Validation.verify_chain ~host:None ~time ~revoked ~anchors:[ca] [cert ; ica] with
    | Ok _ -> Alcotest.fail "expected revocation"
    | Error (`Revoked _) -> ()
    | Error _ -> Alcotest.fail "expected revoked failure!"

let crl'leaf () =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = "\x42" in
  let ica, ipub, ipriv = cert ~name:"subCA" now true capub capriv (Certificate.subject ca) in
  let issuer = Certificate.subject ica in
  let cert, _pub, _priv = cert ~serial now false ipub ipriv issuer in
  let revoked = { CRL.serial ; date = now ; extensions = Extension.empty } in
  let extensions = Extension.(singleton CRL_number (false, 1)) in
  match CRL.revoke ~issuer ~this_update:now ~extensions [revoked] ipriv with
  | Error _ -> Alcotest.fail "couldn't revoke"
  | Ok crl ->
    let revoked = CRL.is_revoked [crl] ?allowed_hashes:None in
    match Validation.verify_chain ~host:None ~time ~revoked ~anchors:[ca] [cert ; ica] with
    | Ok _ -> Alcotest.fail "expected revocation"
    | Error (`Revoked _) -> ()
    | Error _ -> Alcotest.fail "expected revoked failure!"

let crl'leaf'wrong () =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" now true capub capriv issuer in
  let cert, _pub, _priv = cert ~serial now false ipub ipriv (Certificate.subject ica) in
  let revoked = { CRL.serial ; date = now ; extensions = Extension.empty } in
  let extensions = Extension.(singleton CRL_number (false, 1)) in
  match CRL.revoke ~issuer ~this_update:now ~extensions [revoked] ipriv with
  | Error _ -> Alcotest.fail "couldn't revoke"
  | Ok crl ->
    let revoked = CRL.is_revoked [crl] ?allowed_hashes:None in
    match Validation.verify_chain ~host:None ~time ~revoked ~anchors:[ca] [cert ; ica] with
    | Ok _ -> ()
    | Error _ -> Alcotest.fail "expected success!"

let verify'' () =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" now true capub capriv issuer in
  let cert, _pub, _priv = cert now false ipub ipriv (Certificate.subject ica) in
  let revoked = { CRL.serial ; date = now ; extensions = Extension.empty } in
  let extensions = Extension.(singleton CRL_number (false, 1)) in
  match CRL.revoke ~issuer ~this_update:now ~extensions [revoked] capriv with
  | Error _ -> Alcotest.fail "couldn't revoke"
  | Ok crl ->
    let revoked = CRL.is_revoked [crl] ?allowed_hashes:None in
    match Validation.verify_chain ~host:None ~time ~revoked ~anchors:[ca] [cert ; ica] with
    | Ok _ -> ()
    | Error _ -> Alcotest.fail "expected verify to succeed!"

let crl'' () =
  let now = Ptime_clock.now () in
  let ca, capub, capriv = selfsigned now in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let ica, ipub, ipriv = cert ~name:"subCA" ~serial now true capub capriv issuer in
  let cert, _pub, _priv = cert now false ipub ipriv (Certificate.subject ica) in
  let extensions = Extension.(singleton Reason (false, `Remove_from_CRL)) in
  let revoked = { CRL.serial ; date = now ; extensions } in
  let extensions = Extension.(singleton CRL_number (false, 1)) in
  match CRL.revoke ~issuer ~this_update:now ~extensions [revoked] capriv with
  | Error _ -> Alcotest.fail "couldn't revoke"
  | Ok crl ->
    let revoked = CRL.is_revoked [crl] ?allowed_hashes:None in
    match Validation.verify_chain ~host:None ~time ~revoked ~anchors:[ca] [cert ; ica] with
    | Ok _ -> ()
    | Error _ -> Alcotest.fail "expected proper verification!"

let revoke_tests = [
  "Permitted name constraints form a union", `Quick, name_constraints_union ;
  "Permitted IP name constraints form a union", `Quick, ip_name_constraints_union ;
  "Every DNS SAN must be permitted", `Quick, name_constraints_all_dns_names ;
  "Excluded names take precedence", `Quick, name_constraints_excluded ;
  "Permitted names intersect across CAs", `Quick, name_constraints_chain ;
  "Verify with a chain works", `Quick, verify ;
  "Verify with a revoked leaf fails", `Quick, crl ;
  "Verify with a longer chain works", `Quick, verify' ;
  "Verify with a revoked intermediate fails", `Quick, crl' ;
  "Verify with a longer chain works, even if some random serial is revoked", `Quick, verify'' ;
  "Verify with a revoked `Remove_from_CRL works", `Quick, crl'' ;
  "Verify with revoked leaf fails", `Quick, crl'leaf ;
  "Verify with wrongly revoked leaf works", `Quick, crl'leaf'wrong ;
]
