open X509

open Utils

let time () = None

(* some revocation scenarios to convince myself *)
let verify () =
  let now = Ptime_clock.now () in
  let _, capriv = key () in
  let ca = selfsigned ~now ~priv:capriv (ca_exts ()) in
  let _, priv = key () in
  let cert = cert ~now ~ca_key:capriv ~priv leaf_exts (Certificate.subject ca) in
  match Validation.verify_chain ~host:None ~time ~anchors:[ca] [cert] with
  | Ok _ -> ()
  | Error _ -> Alcotest.fail "expected verification to succeed"

let crl () =
  let now = Ptime_clock.now () in
  let _, capriv = key () in
  let ca = selfsigned ~now ~priv:capriv (ca_exts ()) in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let _, priv = key () in
  let cert = cert ~now ~ca_key:capriv ~priv ~serial leaf_exts issuer in
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
  let _, capriv = key () in
  let ca = selfsigned ~now ~priv:capriv (ca_exts ()) in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let _, impriv = key () in
  let ica = cert ~now ~ca_key:capriv ~priv:impriv ~name:(cn "subCA") ~serial (ca_exts ()) issuer in
  let _, priv = key () in
  let cert = cert ~now ~ca_key:impriv ~priv leaf_exts (Certificate.subject ica) in
  match Validation.verify_chain ~host:None ~time ~anchors:[ca] [cert ; ica] with
  | Ok _ -> ()
  | Error _ -> Alcotest.fail "expected verification!"

let crl' () =
  let now = Ptime_clock.now () in
  let _, capriv = key () in
  let ca = selfsigned ~now ~priv:capriv (ca_exts ()) in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let _, impriv = key () in
  let ica = cert ~now ~ca_key:capriv ~priv:impriv ~name:(cn "subCA") ~serial (ca_exts ()) issuer in
  let _, priv = key () in
  let cert = cert ~now ~ca_key:impriv ~priv leaf_exts (Certificate.subject ica) in
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
  let _, capriv = key () in
  let ca = selfsigned ~now ~priv:capriv (ca_exts ()) in
  let serial = "\x42" in
  let _, impriv = key () in
  let ica = cert ~now ~ca_key:capriv ~priv:impriv ~name:(cn "subCA") (ca_exts ()) (Certificate.subject ca) in
  let issuer = Certificate.subject ica in
  let _, priv = key () in
  let cert = cert ~now ~ca_key:impriv ~priv ~serial leaf_exts issuer in
  let revoked = { CRL.serial ; date = now ; extensions = Extension.empty } in
  let extensions = Extension.(singleton CRL_number (false, 1)) in
  match CRL.revoke ~issuer ~this_update:now ~extensions [revoked] impriv with
  | Error _ -> Alcotest.fail "couldn't revoke"
  | Ok crl ->
    let revoked = CRL.is_revoked [crl] ?allowed_hashes:None in
    match Validation.verify_chain ~host:None ~time ~revoked ~anchors:[ca] [cert ; ica] with
    | Ok _ -> Alcotest.fail "expected revocation"
    | Error (`Revoked _) -> ()
    | Error _ -> Alcotest.fail "expected revoked failure!"

let crl'leaf'wrong () =
  let now = Ptime_clock.now () in
  let _, capriv = key () in
  let ca = selfsigned ~now ~priv:capriv (ca_exts ()) in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let _, impriv = key () in
  let ica = cert ~now ~ca_key:capriv ~priv:impriv ~name:(cn "subCA") (ca_exts ()) issuer in
  let _, priv = key () in
  let cert = cert ~now ~ca_key:impriv ~priv ~serial leaf_exts (Certificate.subject ica) in
  let revoked = { CRL.serial ; date = now ; extensions = Extension.empty } in
  let extensions = Extension.(singleton CRL_number (false, 1)) in
  match CRL.revoke ~issuer ~this_update:now ~extensions [revoked] impriv with
  | Error _ -> Alcotest.fail "couldn't revoke"
  | Ok crl ->
    let revoked = CRL.is_revoked [crl] ?allowed_hashes:None in
    match Validation.verify_chain ~host:None ~time ~revoked ~anchors:[ca] [cert ; ica] with
    | Ok _ -> ()
    | Error _ -> Alcotest.fail "expected success!"

let verify'' () =
  let now = Ptime_clock.now () in
  let _, capriv = key () in
  let ca = selfsigned ~now ~priv:capriv (ca_exts ()) in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let _, impriv = key () in
  let ica = cert ~now ~ca_key:capriv ~priv:impriv ~name:(cn "subCA") (ca_exts ()) issuer in
  let _, priv = key () in
  let cert = cert ~now ~ca_key:impriv ~priv leaf_exts (Certificate.subject ica) in
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
  let _, capriv = key () in
  let ca = selfsigned ~now ~priv:capriv (ca_exts ()) in
  let serial = "\x42" in
  let issuer = Certificate.subject ca in
  let _, impriv = key () in
  let ica = cert ~now ~ca_key:capriv ~priv:impriv ~name:(cn "subCA") ~serial (ca_exts ()) issuer in
  let _, priv = key () in
  let cert = cert ~now ~ca_key:impriv ~priv leaf_exts (Certificate.subject ica) in
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
  "Verify with a chain works", `Quick, verify ;
  "Verify with a revoked leaf fails", `Quick, crl ;
  "Verify with a longer chain works", `Quick, verify' ;
  "Verify with a revoked intermediate fails", `Quick, crl' ;
  "Verify with a longer chain works, even if some random serial is revoked", `Quick, verify'' ;
  "Verify with a revoked `Remove_from_CRL works", `Quick, crl'' ;
  "Verify with revoked leaf fails", `Quick, crl'leaf ;
  "Verify with wrongly revoked leaf works", `Quick, crl'leaf'wrong ;
]
