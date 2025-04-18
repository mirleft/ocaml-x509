(*
 * X509 certs
 *)
type tBSCertificate = {
  version    : [ `V1 | `V2 | `V3 ] ;
  serial     : string ;
  signature  : Algorithm.t ;
  issuer     : Distinguished_name.t ;
  validity   : Ptime.t * Ptime.t ;
  subject    : Distinguished_name.t ;
  pk_info    : Public_key.t ;
  issuer_id  : string option ;
  subject_id : string option ;
  extensions : Extension.t
}

type certificate = {
  tbs_cert       : tBSCertificate ;
  signature_algo : Algorithm.t ;
  signature_val  : string
}

(*
 * There are two reasons to carry octets around:
 * - we still need to hack on the octets to get bytes to hash
 *   ( this needs to go )
 * - we need a cs to send to the peer
 * It's a bit ugly to have two levels, and both are better solved by extending
 * the asn parser and writer respectively, but until then there needs to be one
 * place that hides the existence of this pair.
 *)
type t = {
  asn : certificate ;
  raw : string
}

module Asn = struct
  open Asn.S
  open Asn_grammars

  let version =
    map (function 2 -> `V3 | 1 -> `V2 | 0 -> `V1 | _ -> parse_error "unknown version")
      (function `V3 -> 2 | `V2 -> 1 | `V1 -> 0)
      int

  let time =
    let f = function `C1 t -> t | `C2 t -> t
    and g t =
      let (y, _, _) = Ptime.to_date t in
      if y < 2050 then `C1 t else `C2 t in
    map f g (choice2 utc_time generalized_time_no_frac_s)

  let validity =
    sequence2
      (required ~label:"not before" time)
      (required ~label:"not after"  time)

  let unique_identifier = bit_string_octets

  let tBSCertificate =
    let f = fun (a, (b, (c, (d, (e, (f, (g, (h, (i, j))))))))) ->
      let extn = match j with None -> Extension.empty | Some xs -> xs in
      { version    = Option.value ~default:`V1 a ; serial     = b ;
        signature  = c         ; issuer     = d ;
        validity   = e         ; subject    = f ;
        pk_info    = g         ; issuer_id  = h ;
        subject_id = i         ; extensions = extn }
    and g = fun
      { version    = a ; serial     = b ;
        signature  = c ; issuer     = d ;
        validity   = e ; subject    = f ;
        pk_info    = g ; issuer_id  = h ;
        subject_id = i ; extensions = j } ->
      let extn = if Extension.is_empty j then None else Some j in
      ((if a = `V1 then None else Some a),
       (b, (c, (d, (e, (f, (g, (h, (i, extn)))))))))
    in
    map f g @@
    sequence @@
    (optional ~label:"version"       @@ explicit 0 version) (* default v1 *)
    @ (required ~label:"serialNumber"  @@ serial)
    @ (required ~label:"signature"     @@ Algorithm.identifier)
    @ (required ~label:"issuer"        @@ Distinguished_name.Asn.name)
    @ (required ~label:"validity"      @@ validity)
    @ (required ~label:"subject"       @@ Distinguished_name.Asn.name)
    @ (required ~label:"subjectPKInfo" @@ Public_key.Asn.pk_info_der)
      (* if present, version is v2 or v3 *)
    @ (optional ~label:"issuerUID"     @@ implicit 1 unique_identifier)
      (* if present, version is v2 or v3 *)
    @ (optional ~label:"subjectUID"    @@ implicit 2 unique_identifier)
      (* v3 if present *)
   -@ (optional ~label:"extensions"    @@ explicit 3 Extension.Asn.extensions_der)

  let (tbs_certificate_of_octets, tbs_certificate_to_octets) =
    projections_of Asn.der tBSCertificate

  let certificate =
    let f (a, b, c) =
      if a.signature <> b then
        parse_error "signatureAlgorithm != tbsCertificate.signature"
      else
        { tbs_cert = a; signature_algo = b; signature_val = c }
    and g { tbs_cert = a; signature_algo = b; signature_val = c } = (a, b, c) in
    map f g @@
    sequence3
      (required ~label:"tbsCertificate"     tBSCertificate)
      (required ~label:"signatureAlgorithm" Algorithm.identifier)
      (required ~label:"signatureValue"     bit_string_octets)

  let (certificate_of_octets, certificate_to_octets) =
    projections_of Asn.der certificate

  let pkcs1_digest_info =
    let open Algorithm in
    let f (algo, cs) =
      match to_hash algo with
      | Some h -> (h, cs)
      | None   -> parse_error "pkcs1 digest info: unknown hash"
    and g (h, cs) = (of_hash h, cs)
    in
    map f g @@
    sequence2
      (required ~label:"digestAlgorithm" Algorithm.identifier)
      (required ~label:"digest"          octet_string)

  let (pkcs1_digest_info_of_octets, pkcs1_digest_info_to_octets) =
    projections_of Asn.der pkcs1_digest_info
end

let decode_pkcs1_digest_info cs =
  Asn_grammars.err_to_msg (Asn.pkcs1_digest_info_of_octets cs)

let encode_pkcs1_digest_info = Asn.pkcs1_digest_info_to_octets

let ( let* ) = Result.bind

let decode_der cs =
  let* asn = Asn_grammars.err_to_msg (Asn.certificate_of_octets cs) in
  Ok { asn ; raw = cs }

let encode_der { raw ; _ } = raw

let decode_pem_multiple cs =
  let* data = Pem.parse cs in
  let certs =
    List.filter (fun (t, _) -> String.equal "CERTIFICATE" t) data
  in
  Pem.foldM (fun (_, cs) -> decode_der cs) certs

let fold_decode_pem_multiple fn acc cs =
  List.fold_left
    (fun acc data ->
      let data = match data with
        | Ok ("CERTIFICATE", cs) -> decode_der cs
        | Ok (hdr, _) -> Error (`Msg ("ignore non certificate (" ^ hdr ^ ")"))
        | Error e -> Error e
      in
      fn acc data)
    acc
    (Pem.parse_with_errors cs)

let decode_pem cs =
  let* certs = decode_pem_multiple cs in
  Pem.exactly_one ~what:"certificate" certs

let encode_pem v =
  Pem.unparse ~tag:"CERTIFICATE" (encode_der v)

let encode_pem_multiple cs =
  String.concat "" (List.map encode_pem cs)

let pp_version ppf v =
  Fmt.string ppf (match v with `V1 -> "1" | `V2 -> "2" | `V3 -> "3")

let pp_hash ppf hash =
  Fmt.string ppf (match hash with
      | `MD5 -> "MD5" | `SHA1 -> "SHA1" | `SHA224 -> "SHA224"
      | `SHA256 -> "SHA256" | `SHA384 -> "SHA384" | `SHA512 -> "SHA512")

let pp_sigalg ppf (asym, hash) =
  Fmt.pf ppf "%a-%a" Key_type.pp_signature_scheme asym pp_hash hash

let pp' pp_custom_extensions ppf { asn ; _ } =
  let tbs = asn.tbs_cert in
  let sigalg = Algorithm.to_signature_algorithm tbs.signature in
  Fmt.pf ppf "X.509 certificate@.version %a@.serial %a@.algorithm %a@.issuer %a@.valid from %a until %a@.subject %a@.extensions %a"
    pp_version tbs.version Ohex.pp tbs.serial
    Fmt.(option ~none:(any "NONE") pp_sigalg) sigalg
    Distinguished_name.pp tbs.issuer
    (Ptime.pp_human ~tz_offset_s:0 ()) (fst tbs.validity)
    (Ptime.pp_human ~tz_offset_s:0 ()) (snd tbs.validity)
    Distinguished_name.pp tbs.subject
    (Extension.pp' pp_custom_extensions) tbs.extensions

let pp = pp' Extension.default_pp_custom_extension

let fingerprint hash cert =
  let module Hash = (val (Digestif.module_of_hash' hash)) in
  Hash.(to_raw_string (digest_string cert.raw))

let issuer { asn ; _ } = asn.tbs_cert.issuer

let subject { asn ; _ } = asn.tbs_cert.subject

let serial { asn ; _ } = asn.tbs_cert.serial

let validity { asn ; _ } = asn.tbs_cert.validity

let signature_algorithm { asn ; _ } =
  Algorithm.to_signature_algorithm asn.signature_algo

let public_key { asn = cert ; _ } = cert.tbs_cert.pk_info

let supports_keytype c t =
  match public_key c, t with
  | (`RSA _), `RSA -> true
  | _              -> false

let extensions { asn = cert ; _ } = cert.tbs_cert.extensions

(* RFC 6125, 6.4.4:
   Therefore, if and only if the presented identifiers do not include a
   DNS-ID, SRV-ID, URI-ID, or any application-specific identifier types
   supported by the client, then the client MAY as a last resort check
   for a string whose form matches that of a fully qualified DNS domain
   name in a Common Name field of the subject field (i.e., a CN-ID).  If
   the client chooses to compare a reference identifier of type CN-ID
   against that string, it MUST follow the comparison rules for the DNS
   domain name portion of an identifier of type DNS-ID, SRV-ID, or
   URI-ID, as described under Section 6.4.1, Section 6.4.2, and
   Section 6.4.3. *)
let hostnames { asn = cert ; _ } =
  let subj =
    match Distinguished_name.common_name cert.tbs_cert.subject with
    | None -> Host.Set.empty
    | Some x ->
      match Host.host x with
      | Some (wild, d) -> Host.Set.singleton (wild, d)
      | None -> Host.Set.empty
  in
  match Extension.hostnames cert.tbs_cert.extensions with
  | Some names -> names
  | None -> subj

let supports_hostname cert name =
  let names = hostnames cert in
  let wc_name_opt =
    match Domain_name.drop_label name with
    | Error _ -> None
    | Ok name -> match Domain_name.host name with
      | Ok hostname -> Some hostname
      | Error _ -> None
  in
  Host.Set.mem (`Strict, name) names
  || (match wc_name_opt with
      | None -> false
      | Some wc_name -> Host.Set.mem (`Wildcard, wc_name) names)

let ips { asn = cert ; _ } =
  match Extension.ips cert.tbs_cert.extensions with
  | None -> Ipaddr.Set.empty
  | Some ips -> ips

let supports_ip cert ip = Ipaddr.Set.mem ip (ips cert)
