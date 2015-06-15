open X509_certificate

open Asn_grammars

let raw_sign raw digest key =
  let hash = Nocrypto.Hash.digest digest raw in
  let sigval = pkcs1_digest_info_to_cstruct (digest, hash) in
  match key with
    | `RSA priv -> Nocrypto.Rsa.PKCS1.sign ~key:priv sigval

open CertificateRequest

type signing_request = certificate_request * Cstruct.t option

type request_info_extensions = [
  | `Password of string
  | `Name of string
  | `Extensions of (bool * Extension.t) list
]

let validate_signature (csr, raw) =
  let raw = match raw with
    | None -> certificate_request_info_to_cs csr.info
    | Some x -> raw_cert_hack x csr.signature
  in
  validate_raw_signature raw csr.signature_algorithm csr.signature csr.info.public_key

let parse_signing_request cs =
  match certificate_request_of_cs cs with
  | Some csr when validate_signature (csr, Some cs) ->
    Some (csr, Some cs)
  | _ -> None

let cs_of_signing_request (csr, raw) =
  match raw with
  | Some x -> x
  | None -> certificate_request_to_cs csr

type privkey = [ `RSA of Nocrypto.Rsa.priv ]

let privkey_to_keytype = function
  | `RSA _ -> `RSA

let generate subject ?(digest = `SHA256) ?(extensions = None) = function
  | `RSA priv ->
    let public_key = `RSA (Nocrypto.Rsa.pub_of_priv priv) in
    let info = { subject ; public_key ; extensions } in
    let info_cs = certificate_request_info_to_cs info in
    let signature = raw_sign info_cs digest (`RSA priv) in
    let signature_algorithm = Algorithm.of_signature_algorithm `RSA digest in
    ({ info ; signature_algorithm ; signature }, None)

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

let sign signing_request
    ?(digest = `SHA256)
    ?(valid_from = Unix.gmtime (Unix.time ()))
    ?(valid_until = Unix.gmtime (Unix.time () +. 86400.))
    ?(serial = Nocrypto.(Rng.Z.gen_r Numeric.Z.one Numeric.Z.(one lsl 64)))
    ?(extensions = [])
    key issuer =
  assert (validate_signature signing_request) ;
  let from = tm_to_asn valid_from
  and until = tm_to_asn valid_until
  and signature_algo =
    Algorithm.of_signature_algorithm (privkey_to_keytype key) digest
  and info = (fst signing_request).info
  in
  let tbs_cert : tBSCertificate = {
      version = `V3 ;
      serial ;
      signature = signature_algo ;
      issuer = issuer ;
      validity = (from, until) ;
      subject = info.subject ;
      pk_info = info.public_key ;
      issuer_id = None ;
      subject_id = None ;
      extensions
  } in
  let tbs_raw = tbs_certificate_to_cstruct tbs_cert in
  let signature_val = raw_sign tbs_raw digest key in
  let asn = {
    tbs_cert ;
    signature_algo ;
    signature_val ;
  } in
  let raw = certificate_to_cstruct asn in
  { asn ; raw }
