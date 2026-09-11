open X509

let key () =
  let key = Mirage_crypto_pk.Rsa.generate ~bits:1024 () in
  (`RSA (Mirage_crypto_pk.Rsa.pub_of_priv key), `RSA key)

let ca_exts ?pathlen () =
  let ku =
    [ `Key_cert_sign ; `CRL_sign ; `Digital_signature ; `Content_commitment ]
  in
  Extension.(add Basic_constraints (true, (true, pathlen))
               (singleton Key_usage (true, ku)))

let leaf_exts =
  Extension.(add Key_usage (true, [ `Digital_signature ; `Key_encipherment ])
               (add Ext_key_usage (true, [ `Server_auth ])
                  (singleton Basic_constraints (true, (false, None)))))

let key_ids exts subject_pubkey issuer_pubkey =
  let subject_key_id =
    false, Public_key.id subject_pubkey
  and authority_key_id =
    let cs = Public_key.id issuer_pubkey in
    false, (Some cs, General_name.empty, None)
  in
  Extension.(add Subject_key_id subject_key_id
               (add Authority_key_id authority_key_id exts))

let validity now =
  Option.get (Ptime.sub_span now (Ptime.Span.of_int_s 10)),
  Option.get (Ptime.add_span now (Ptime.Span.of_int_s 10))

let cn name =
  [ Distinguished_name.(Relative_distinguished_name.singleton
                          (CN (Common_name.v name))) ]

let selfsigned ~now ~priv ?(name = cn "test") ?serial extensions =
  match Signing_request.create name priv with
  | Error _ -> assert false
  | Ok req ->
    let valid_from, valid_until = validity now in
    match Signing_request.sign req ~valid_from ~valid_until ?serial ~extensions priv name with
    | Ok cacert -> cacert
    | Error _ -> assert false

let cert ~now ~ca_key ~priv ?serial ?(name = cn "sub") extensions issuer =
  match Signing_request.create name priv with
  | Error _ -> assert false
  | Ok req ->
    let valid_from, valid_until = validity now in
    let pub = Private_key.public priv
    and ca_pub = Private_key.public ca_key
    in
    let extensions = key_ids extensions pub ca_pub in
    match X509.Signing_request.sign req ~valid_from ~valid_until ?serial ~extensions ca_key issuer with
    | Ok cert -> cert
    | Error _ -> assert false
