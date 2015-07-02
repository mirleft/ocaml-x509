open X509_certificate

open Asn_grammars

let raw_sign raw digest key =
  let hash = Nocrypto.Hash.digest digest raw in
  let sigval = pkcs1_digest_info_to_cstruct (digest, hash) in
  match key with
    | `RSA priv -> Nocrypto.Rsa.PKCS1.sig_encode ~key:priv sigval

type signing_request = CertificateRequest.certificate_request * Cstruct.t option

type request_extensions = X509_types.request_extensions

let validate_signature ({ CertificateRequest.info ; signature ; signature_algorithm }, raw) =
  let raw = match raw with
    | None -> CertificateRequest.certificate_request_info_to_cs info
    | Some x -> raw_cert_hack x signature
  in
  validate_raw_signature
    raw
    signature_algorithm
    signature
    info.CertificateRequest.public_key

let parse_signing_request cs =
  match CertificateRequest.certificate_request_of_cs cs with
  | Some csr when validate_signature (csr, Some cs) ->
    Some (csr, Some cs)
  | _ -> None

let cs_of_signing_request (csr, raw) =
  match raw with
  | Some x -> x
  | None -> CertificateRequest.certificate_request_to_cs csr

let request subject ?(digest = `SHA256) ?(extensions = []) = function
  | `RSA priv ->
    let public_key = `RSA (Nocrypto.Rsa.pub_of_priv priv) in
    let info = { CertificateRequest.subject ; public_key ; extensions } in
    let info_cs = CertificateRequest.certificate_request_info_to_cs info in
    let signature = raw_sign info_cs digest (`RSA priv) in
    let signature_algorithm = Algorithm.of_signature_algorithm `RSA digest in
    ({ CertificateRequest.info ; signature_algorithm ; signature }, None)

let sign signing_request
    ~valid_from ~valid_until
    ?(digest = `SHA256)
    ?(serial = Nocrypto.(Rng.Z.gen_r Numeric.Z.one Numeric.Z.(one lsl 64)))
    ?(extensions = [])
    key issuer =
  assert (validate_signature signing_request) ;
  let signature_algo =
    Algorithm.of_signature_algorithm (private_key_to_keytype key) digest
  and info = (fst signing_request).CertificateRequest.info
  in
  let tbs_cert : tBSCertificate = {
      version = `V3 ;
      serial ;
      signature = signature_algo ;
      issuer = issuer ;
      validity = (valid_from, valid_until) ;
      subject = info.CertificateRequest.subject ;
      pk_info = info.CertificateRequest.public_key ;
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

module Util = struct
    let extensions signing_request =
      let info = (fst signing_request).CertificateRequest.info in
      info.CertificateRequest.extensions

    type input = [
      | `CSR of signing_request
      | `CERT of t
    ]

    let key_id = function
      | `RSA p -> Nocrypto.Hash.digest `SHA1 (PK.rsa_public_to_cstruct p)
      | `EC_pub _ -> invalid_arg "ECDSA not implemented"

    let subject_key_id = function
      | `CSR csr ->
         let info = (fst csr).CertificateRequest.info in
         key_id info.CertificateRequest.public_key
      | `CERT cert ->
         key_id (public_key cert)
end
