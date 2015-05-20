open X509_certificate

open Asn_grammars

type signing_request = (Name.dn * pubkey)

type privkey = [ `RSA of Nocrypto.Rsa.priv ]

let privkey_to_keytype = function
  | `RSA _ -> `RSA

let generate name = function
  | `RSA priv -> (name, `RSA (Nocrypto.Rsa.pub_of_priv priv))

(* move to Asn_time? *)
let tm_to_asn t =
  let open Unix in
  let y = t.tm_year + 1900
  and m = t.tm_mon + 1
  and d = t.tm_mday
  and hh = t.tm_hour
  and mm = t.tm_min
  and ss = t.tm_sec
  in
  Asn.Time.({ date = (y, m, d) ; time = (hh ,mm, ss, 0.) ; tz = None })

let sign (subject, pubkey)
    ?(digest = `SHA1)
    ?(valid_from = Unix.gmtime (Unix.time ()))
    ?(valid_until = Unix.gmtime (Unix.time () +. 86400.))
    ?(serial = Nocrypto.(Rng.Z.gen_r Numeric.Z.one Numeric.Z.(one lsl 64)))
    ?(extensions = [])
    key issuer =
  let from = tm_to_asn valid_from
  and until = tm_to_asn valid_until
  and signature_algo =
    Algorithm.of_signature_algorithm (privkey_to_keytype key) digest
  in
  let tbs : tBSCertificate = {
      version = `V3 ;
      serial ;
      signature = signature_algo ;
      issuer = issuer ;
      validity = (from, until) ;
      subject = subject ;
      pk_info = pubkey ;
      issuer_id = None ;
      subject_id = None ;
      extensions
  } in
  let tbs_raw = tbs_certificate_to_cstruct tbs in
  let hash = Nocrypto.Hash.digest digest tbs_raw in
  let sigval = pkcs1_digest_info_to_cstruct (digest, hash) in
  let signature = match key with
    | `RSA priv -> Nocrypto.Rsa.PKCS1.sign ~key:priv sigval
  in
  let asn = {
    tbs_cert = tbs ;
    signature_algo = signature_algo ;
    signature_val = signature ;
  } in
  let raw = certificate_to_cstruct asn in
  { asn ; raw }
