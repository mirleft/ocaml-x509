type request_extensions = [
  | `Password of string
  | `Name of string
  | `Extensions of (bool * Extension.t) list
]

type request_info = {
  subject : Distinguished_name.t ;
  public_key : Public_key.t ;
  extensions : request_extensions list ;
}

type t = {
  info : request_info ;
  signature_algorithm : Algorithm.t ;
  signature : Cstruct.t
}

module Asn = struct
  open Asn_grammars
  open Asn.S
  open Registry

  let attributes =
    let f = function[@ocaml.warning "-8"]
      | (oid, [`C1 p]) when oid = PKCS9.challenge_password -> `Password p
      | (oid, [`C1 n]) when oid = PKCS9.unstructured_name -> `Name n
      | (oid, [`C2 es]) when oid = PKCS9.extension_request -> `Extensions es
    and g = function
      | `Password p -> (PKCS9.challenge_password, [`C1 p])
      | `Name n -> (PKCS9.unstructured_name, [`C1 n])
      | `Extensions es -> (PKCS9.extension_request, [`C2 es])
    in
    map f g @@
    sequence2
      (required ~label:"attr type" oid)
      (required ~label:"attr value"
         (set_of (choice2
                    utf8_string
                    Extension.Asn.extensions_der)))

  let request_info =
    let f = function
      | (0, subject, public_key, extensions) ->
        { subject ; public_key ; extensions }
      | _ ->
        parse_error "unknown certificate request info"
    and g { subject ; public_key ; extensions } =
      (0, subject, public_key, extensions)
    in
    map f g @@
    sequence4
      (required ~label:"version" int)
      (required ~label:"subject" Distinguished_name.Asn.name)
      (required ~label:"subjectPKInfo" Public_key.Asn.pk_info_der)
      (required ~label:"attributes" @@ implicit 0 (set_of attributes))

  let request_info_of_cs, request_info_to_cs =
    projections_of Asn.der request_info

  let signing_request =
    let f = fun (info, signature_algorithm, signature) ->
      { info ; signature_algorithm ; signature }
    and g = fun { info ; signature_algorithm ; signature } ->
      (info, signature_algorithm, signature)
    in
    map f g @@
    sequence3
      (required ~label:"certificationRequestInfo" request_info)
      (required ~label:"signatureAlgorithm" Algorithm.identifier)
      (required ~label:"signature" bit_string_cs)

  let signing_request_of_cs, signing_request_to_cs =
    projections_of Asn.der signing_request
end

let raw_sign raw digest key =
  let hash = Nocrypto.Hash.digest digest raw in
  let sigval = Certificate.encode_pkcs1_digest_info (digest, hash) in
  match key with
    | `RSA priv -> Nocrypto.Rsa.PKCS1.sig_encode ~key:priv sigval

let info sr = sr.info

let validate_signature { info ; signature ; signature_algorithm } =
  (* TODO: may be wrong if remote used some non-utf string encoding *)
  let raw = Asn.request_info_to_cs info in
  Validation.validate_raw_signature raw signature_algorithm signature info.public_key

let decode_der cs =
  let open Rresult.R.Infix in
  Asn.signing_request_of_cs cs >>= fun csr ->
  if validate_signature csr then
    Ok csr
  else
    Error (`Parse "couldn't validate signature")

let encode_der = Asn.signing_request_to_cs

let decode_pem cs =
  let open Rresult.R.Infix in
  Pem.parse cs >>= fun data ->
  let crs =
    List.filter (fun (t, _) -> String.equal "CERTIFICATE REQUEST" t) data
  in
  Pem.foldM (fun (_, cs) -> decode_der cs) crs >>=
  Pem.exactly_one ~what:"certificate request"

let encode_pem v =
  Pem.unparse ~tag:"CERTIFICATE REQUEST" (encode_der v)

let create subject ?(digest = `SHA256) ?(extensions = []) = function
  | `RSA priv ->
    let public_key = `RSA (Nocrypto.Rsa.pub_of_priv priv) in
    let info : request_info = { subject ; public_key ; extensions } in
    let info_cs = Asn.request_info_to_cs info in
    let signature = raw_sign info_cs digest (`RSA priv) in
    let signature_algorithm = Algorithm.of_signature_algorithm `RSA digest in
    { info ; signature_algorithm ; signature }

let sign signing_request
    ~valid_from ~valid_until
    ?(digest = `SHA256)
    ?(serial = Nocrypto.(Rng.Z.gen_r Numeric.Z.one Numeric.Z.(one lsl 64)))
    ?(extensions = [])
    key issuer =
  assert (validate_signature signing_request);
  let signature_algo =
    Algorithm.of_signature_algorithm (Private_key.keytype key) digest
  and info = signing_request.info
  in
  let tbs_cert : Certificate.tBSCertificate = {
      version = `V3 ;
      serial ;
      signature = signature_algo ;
      issuer = issuer ;
      validity = (valid_from, valid_until) ;
      subject = info.subject ;
      pk_info = info.public_key ;
      issuer_id = None ;
      subject_id = None ;
      extensions
  } in
  let tbs_raw = Certificate.Asn.tbs_certificate_to_cstruct tbs_cert in
  let signature_val = raw_sign tbs_raw digest key in
  let asn = {
    Certificate.tbs_cert ;
    signature_algo ;
    signature_val ;
  } in
  let raw = Certificate.Asn.certificate_to_cstruct asn in
  { Certificate.asn ; raw }
