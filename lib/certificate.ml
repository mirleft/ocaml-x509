open Nocrypto
open Astring

open Common

type key_type = [ `RSA | `EC of Asn.oid ]

(*
 * X509 certs
 *)
type tBSCertificate = {
  version    : [ `V1 | `V2 | `V3 ] ;
  serial     : Z.t ;
  signature  : Algorithm.t ;
  issuer     : Distinguished_name.t ;
  validity   : Ptime.t * Ptime.t ;
  subject    : Distinguished_name.t ;
  pk_info    : Public_key.t ;
  issuer_id  : Cstruct.t option ;
  subject_id : Cstruct.t option ;
  extensions : (bool * Extension.t) list
}

type certificate = {
  tbs_cert       : tBSCertificate ;
  signature_algo : Algorithm.t ;
  signature_val  : Cstruct.t
}

(*
 * There are two reasons to carry Cstruct.t around:
 * - we still need to hack on the cstruct to get bytes to hash
 *   ( this needs to go )
 * - we need a cs to send to the peer
 * It's a bit ugly to have two levels, and both are better solved by extending
 * the asn parser and writer respectively, but until then there needs to be one
 * place that hides the existence of this pair.
 *)
type t = {
  asn : certificate ;
  raw : Cstruct.t
}

module Asn = struct
  open Asn.S
  open Asn_grammars

  let version =
    map (function 2 -> `V3 | 1 -> `V2 | 0 -> `V1 | _ -> parse_error "unknown version")
      (function `V3 -> 2 | `V2 -> 1 | `V1 -> 0)
      int

  let certificate_sn = integer

  let time =
    let f = function `C1 t -> t | `C2 t -> t
    and g t =
      let (y, _, _) = Ptime.to_date t in
      if y < 2050 then `C1 t else `C2 t in
    map f g (choice2 utc_time generalized_time)

  let validity =
    sequence2
      (required ~label:"not before" time)
      (required ~label:"not after"  time)

  let unique_identifier = bit_string_cs

  let tBSCertificate =
    let f = fun (a, (b, (c, (d, (e, (f, (g, (h, (i, j))))))))) ->
      let extn = match j with None -> [] | Some xs -> xs
      in
      { version    = def `V1 a ; serial     = b ;
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
      let extn = match j with [] -> None | xs -> Some xs
      in
      (def' `V1 a, (b, (c, (d, (e, (f, (g, (h, (i, extn)))))))))
    in
    map f g @@
    sequence @@
    (optional ~label:"version"       @@ explicit 0 version) (* default v1 *)
    @ (required ~label:"serialNumber"  @@ certificate_sn)
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

  let (tbs_certificate_of_cstruct, tbs_certificate_to_cstruct) =
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
      (required ~label:"signatureValue"     bit_string_cs)

  let (certificate_of_cstruct, certificate_to_cstruct) =
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

  let (pkcs1_digest_info_of_cstruct, pkcs1_digest_info_to_cstruct) =
    projections_of Asn.der pkcs1_digest_info

  (* A bit of accessors for tree-diving. *)
  (*
   * XXX We re-traverse the list over 9000 times. Abstract out the extensions in a
   * cert into sth more efficient at the cost of losing the printer during
   * debugging?
   *)
  let  extn_subject_alt_name
     , extn_issuer_alt_name
     , extn_authority_key_id
     , extn_subject_key_id
     , extn_key_usage
     , extn_ext_key_usage
     , extn_basic_constr
     , extn_priv_key_period
     , extn_name_constraints
     , extn_crl_distribution_points
     , extn_policies
    =
    let f pred cert =
      List_ext.map_find cert.tbs_cert.extensions
        ~f:(fun (crit, ext) ->
            match pred ext with None -> None | Some x -> Some (crit, x))
    in
    (f @@ function `Subject_alt_name  _ as x -> Some x | _ -> None),
    (f @@ function `Issuer_alt_name   _ as x -> Some x | _ -> None),
    (f @@ function `Authority_key_id  _ as x -> Some x | _ -> None),
    (f @@ function `Subject_key_id    _ as x -> Some x | _ -> None),
    (f @@ function `Key_usage         _ as x -> Some x | _ -> None),
    (f @@ function `Ext_key_usage     _ as x -> Some x | _ -> None),
    (f @@ function `Basic_constraints _ as x -> Some x | _ -> None),
    (f @@ function `Priv_key_period   _ as x -> Some x | _ -> None),
    (f @@ function `Name_constraints  _ as x -> Some x | _ -> None),
    (f @@ function `CRL_distribution_points  _ as x -> Some x | _ -> None),
    (f @@ function `Policies          _ as x -> Some x | _ -> None)

  let extn_unknown cert oid =
    List_ext.map_find cert.tbs_cert.extensions
      ~f:(fun (crit, ext) ->
          match ext with
          | `Unsupported (o, v) when o = oid -> Some (crit, v)
          | _ -> None)
end

let decode_pkcs1_digest_info, encode_pkcs1_digest_info =
  Asn.(pkcs1_digest_info_of_cstruct, pkcs1_digest_info_to_cstruct)

let decode_der cs =
  let open Rresult.R.Infix in
  Asn.certificate_of_cstruct cs >>| fun asn ->
  { asn ; raw = cs }

let encode_der { raw ; _ } = raw

let decode_pem_multiple cs =
  let open Rresult.R.Infix in
  Pem.parse cs >>= fun data ->
  let certs = List.filter (fun (t, _) -> String.equal "CERTIFICATE" t) data in
  Pem.foldM (fun (_, cs) -> decode_der cs) certs

let decode_pem cs =
  let open Rresult.R.Infix in
  decode_pem_multiple cs >>= Pem.exactly_one ~what:"certificate"

let encode_pem v =
  Pem.unparse ~tag:"CERTIFICATE" (encode_der v)

let encode_pem_multiple cs =
  Cstruct.concat (List.map encode_pem cs)

let pp_version ppf v =
  Fmt.string ppf (match v with `V1 -> "1" | `V2 -> "2" | `V3 -> "3")

let pp_sigalg ppf (asym, hash) =
  Fmt.pf ppf "%s-%s"
    (match asym with `RSA -> "RSA" | `ECDSA -> "ECDSA")
    (match hash with
     | `MD5 -> "MD5" | `SHA1 -> "SHA1" | `SHA224 -> "SHA224"
     | `SHA256 -> "SHA256" | `SHA384 -> "SHA384" | `SHA512 -> "SHA512")

let pp ppf { asn ; _ } =
  let tbs = asn.tbs_cert in
  let sigalg = Algorithm.to_signature_algorithm tbs.signature in
  Fmt.pf ppf "X.509 certificate@.version %a@.serial %a@.algorithm %a@.issuer %a@.valid from %a until %a@.subject %a@.extensions %d"
    pp_version tbs.version Z.pp_print tbs.serial
    Fmt.(option ~none:(unit "NONE") pp_sigalg) sigalg
    Distinguished_name.pp tbs.issuer
    (Ptime.pp_human ~tz_offset_s:0 ()) (fst tbs.validity)
    (Ptime.pp_human ~tz_offset_s:0 ()) (snd tbs.validity)
    Distinguished_name.pp tbs.subject
    (List.length tbs.extensions)

let fingerprint hash cert = Hash.digest hash cert.raw

let issuer { asn ; _ } = asn.tbs_cert.issuer

let subject { asn ; _ } = asn.tbs_cert.subject

let serial { asn ; _ } = asn.tbs_cert.serial

let validity { asn ; _ } = asn.tbs_cert.validity

let public_key { asn = cert ; _ } = cert.tbs_cert.pk_info

let supports_keytype c t =
  match public_key c, t with
  | (`RSA _), `RSA -> true
  | _              -> false

let subject_common_name cert =
  List_ext.map_find cert.tbs_cert.subject
    ~f:(function `CN n -> Some n | _ -> None)

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
let hostnames { asn = cert ; _ } : string list =
  match Asn.extn_subject_alt_name cert, subject_common_name cert with
  | Some (_, `Subject_alt_name names), _    ->
    List_ext.filter_map
      names
      ~f:(function
          | `DNS x -> Some (String.Ascii.lowercase x)
          | _      -> None)
  | _                              , Some x -> [String.Ascii.lowercase x]
  | _                              , _      -> []

(* we have foo.bar.com and want to split that into ["foo"; "bar"; "com"]
   forbidden: multiple dots "..", trailing dot "foo." *)
let split_labels name =
  let labels = String.cuts ~sep:"." name in
  if List.exists (fun s -> s = "") labels then
    None
  else
    Some labels

let o f g x = f (g x)

type host = [ `Strict of string | `Wildcard of string ]

(* we limit our validation to a single '*' character at the beginning (left-most label)! *)
let wildcard_matches host cert =
  let rec wildcard_hostname_matches hostname wildcard =
    match hostname, wildcard with
    | [_]  , []               -> true
    | x::xs, y::ys when x = y -> wildcard_hostname_matches xs ys
    | _    , _                -> false
  in
  let names = hostnames cert in
  match split_labels host with
  | None      -> false
  | Some lbls ->
    List.map split_labels names |>
    List_ext.filter_map ~f:(function Some ("*"::xs) -> Some xs | _ -> None) |>
    List.exists (o (wildcard_hostname_matches (List.rev lbls)) List.rev)

let supports_hostname cert = function
  | `Strict name ->
    List.mem (String.Ascii.lowercase name) (hostnames cert)
  | `Wildcard name ->
    let name = String.Ascii.lowercase name in
    List.mem name (hostnames cert) ||
    wildcard_matches name cert

let cert_usage { asn = cert ; _ } =
  match Asn.extn_key_usage cert with
  | Some (_, `Key_usage usages) -> Some usages
  | _                           -> None

let supports_usage ?(not_present = false) c u =
  match cert_usage c with
  | Some x -> List.mem u x
  | None   -> not_present

let cert_extended_usage { asn = cert ; _ } =
  match Asn.extn_ext_key_usage cert with
  | Some (_, `Ext_key_usage usages) -> Some usages
  | _                               -> None

let supports_extended_usage ?(not_present = false) c u =
  match cert_extended_usage c with
  | Some x -> List.mem u x
  | None   -> not_present

let basic_constraints { asn ; _ } =
  match Asn.extn_basic_constr asn with
  | Some (_, `Basic_constraints data) -> Some data
  | _ -> None

let unsupported { asn ; _ } oid =
  Asn.extn_unknown asn oid

let subject_alt_names { asn = cert ; _ } =
  match Asn.extn_subject_alt_name cert with
  | Some (_, `Subject_alt_name names) -> names
  | _ -> []

let crl_distribution_points { asn = cert ; _ } =
  match Asn.extn_crl_distribution_points cert with
  | Some (_, `CRL_distribution_points ps) -> ps
  | _ -> []
