open Sexplib.Conv
open Nocrypto

open X509_common
open Registry
open Asn_grammars

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
  asn : Asn_grammars.certificate ;
  raw : Cstruct.t
}

let parse_certificate cs =
  match Asn_grammars.certificate_of_cstruct cs with
  | None     -> None
  | Some asn -> Some { asn ; raw = cs }

let cs_of_cert { raw ; _ } = raw

(* XXX Revisit this - would be lovely to dump the full ASN tree. *)
let t_of_sexp _ = failwith "can't parse cert from sexps"
let sexp_of_t cert = Sexplib.Sexp.List
    [ Sexplib.Sexp.Atom "CERTIFICATE" ;
      Sexplib.Sexp.Atom (Cstruct.to_string (Hash.digest `SHA256 cert.raw)) ]

type key_type = Asn_grammars.Algorithm.public_key

type pubkey = [ `RSA of Nocrypto.Rsa.pub ]

let cert_pubkey { asn = cert ; _ } =
  match cert.tbs_cert.pk_info with
  | PK.RSA pk -> Some (`RSA pk)
  | _         -> None

let supports_keytype c t =
  match cert_pubkey c, t with
  | Some (`RSA _), `RSA -> true
  | _ -> false

let cert_usage { asn = cert ; _ } =
  match extn_key_usage cert with
  | Some (_, Extension.Key_usage usages) -> Some usages
  | _                                    -> None

type key_usage = Extension.key_usage

let supports_usage ?(not_present = false) c u =
  match cert_usage c with
  | Some x -> List.mem u x
  | None   -> not_present

let cert_extended_usage { asn = cert ; _ } =
  match extn_ext_key_usage cert with
  | Some (_, Extension.Ext_key_usage usages) -> Some usages
  | _                                        -> None

type extended_key_usage = Extension.extended_key_usage

let supports_extended_usage ?(not_present = false) c u =
  match cert_extended_usage c with
  | Some x -> List.mem u x
  | None   -> not_present

let subject_common_name cert =
  List_ext.map_find cert.tbs_cert.subject
           ~f:(function Name.CN n -> Some n | _ -> None)

let common_name_to_string { asn = cert ; _ } =
  match subject_common_name cert with
  | None   -> "NO commonName"
  | Some x -> x

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
let cert_hostnames { asn = cert ; _ } : string list =
  let open Extension in
  match extn_subject_alt_name cert, subject_common_name cert with
    | Some (_, Subject_alt_name names), _     ->
       List_ext.filter_map
         names
         ~f:(function
              | General_name.DNS x -> Some (String.lowercase x)
              | _                  -> None)
    | _                              , Some x -> [String.lowercase x]
    | _                              , _      -> []

(* we have foo.bar.com and want to split that into ["foo"; "bar"; "com"]
  forbidden: multiple dots "..", trailing dot "foo." *)
let split_labels name =
  let labels = String_ext.split '.' name in
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
  let names = cert_hostnames cert in
    match split_labels host with
    | None      -> false
    | Some lbls ->
       List.map split_labels names |>
         List_ext.filter_map ~f:(function Some ("*"::xs) -> Some xs | _ -> None) |>
         List.exists (o (wildcard_hostname_matches (List.rev lbls)) List.rev)

let supports_hostname cert = function
  | `Strict name   -> List.mem (String.lowercase name) (cert_hostnames cert)
  | `Wildcard name -> let name = String.lowercase name in
                             List.mem name (cert_hostnames cert) ||
                               wildcard_matches name cert


module Validation = struct
  (* Control flow stuff. Should be imported from a single place. *)

  module Control = struct

    type ('a, 'e) or_error =
      | Ok of 'a
      | Error of 'e

    let (>>=) m f = match m with
      | Ok a      -> f a
      | Error err -> Error err

    let success  = Ok ()
    let fail err = Error err

    let lower = function
      | Ok x      -> `Ok x
      | Error err -> `Fail err

    let is_success = function Ok _ -> true | _ -> false

    let rec iter_m f = function
      | []    -> Ok ()
      | x::xs -> f x >>= fun _ -> iter_m f xs

  end

  include Control

  type validation_error = [
    | `InvalidSignature of t * t
    | `CertificateExpired of t
    | `InvalidExtensions of t
    | `InvalidVersion of t
    | `InvalidPathlen of t
    | `SelfSigned of t
    | `NoTrustAnchor
    | `InvalidServerExtensions of t
    | `InvalidServerName of t
    | `InvalidCA of t
    | `IssuerSubjectMismatch of t * t
    | `AuthorityKeyIdSubjectKeyIdMismatch of t * t
    | `ServerNameNotPresent of t
    | `InvalidFingerprint of t
    | `EmptyCertificateChain
  ] with sexp

  let validation_error_to_string = function
    | `InvalidFingerprint c -> "Invalid Fingerprint: " ^ common_name_to_string c
    | `InvalidSignature (t, c) -> "Invalid Signature: (" ^ common_name_to_string t ^ " does not validate " ^ common_name_to_string c ^ ")"
    | `CertificateExpired c -> "Certificate Expired: " ^ common_name_to_string c
    | `InvalidExtensions c -> "Invalid (intermediate CA/CA) extensions: " ^ common_name_to_string c
    | `InvalidVersion c -> "Invalid X.509 version given the extensions: " ^ common_name_to_string c
    | `InvalidPathlen c -> "Invalid Pathlength: " ^ common_name_to_string c
    | `SelfSigned c -> "Self Signed Certificate: " ^ common_name_to_string c
    | `NoTrustAnchor -> "No Trust Anchor"
    | `InvalidServerExtensions c -> "Invalid Server Extensions: " ^ common_name_to_string c
    | `InvalidServerName c -> "Invalid Server Certificate Name: " ^ common_name_to_string c
    | `InvalidCA c -> "Invalid CA (issuer does not match subject): " ^ common_name_to_string c
    | `IssuerSubjectMismatch (t, c) -> "Issuer of " ^ common_name_to_string c ^ " does not match subject of " ^ common_name_to_string t
    | `AuthorityKeyIdSubjectKeyIdMismatch (t, c) -> "Authority Key ID extension of " ^ common_name_to_string c ^ " does not match Subject Key ID extension of " ^ common_name_to_string t
    | `ServerNameNotPresent c -> "Given server name not in fingerprint list " ^ common_name_to_string c
    | `EmptyCertificateChain -> "The provided certificate chain is empty"

  let maybe_validate_hostname cert = function
    | None   -> true
    | Some x -> supports_hostname cert x

  (* TODO RFC 5280: A certificate MUST NOT include more than one
     instance of a particular extension. *)

  let issuer_matches_subject { asn = parent ; _ } { asn = cert ; _ } =
    Name.equal parent.tbs_cert.subject cert.tbs_cert.issuer

  let is_self_signed cert = issuer_matches_subject cert cert

  (* XXX should return the tbs_cert blob from the parser, this is insane *)
  let raw_cert_hack { asn ; raw } =
    let siglen = Cstruct.len asn.signature_val in
    let off    = if siglen > 128 then 1 else 0 in
    Cstruct.(sub raw 4 (len raw - (siglen + 4 + 19 + off)))

  let validate_signature { asn = trusted ; _ } cert =
    let tbs_raw = raw_cert_hack cert in
    match trusted.tbs_cert.pk_info with

    | PK.RSA issuing_key ->

      ( match Rsa.PKCS1.verify ~key:issuing_key cert.asn.signature_val with
        | None           -> false
        | Some signature ->
          match
            pkcs1_digest_info_of_cstruct signature,
            Algorithm.to_signature_algorithm cert.asn.signature_algo
          with
          | Some (algo, hash), Some (`RSA, h) when h = algo ->
            Uncommon.Cs.equal hash (Hash.digest algo tbs_raw)
          | _ -> false )

    | _ -> false

  let validate_time time { asn = cert ; _ } =
    match time with
    | None     -> true
    | Some now ->
      let (not_before, not_after) = cert.tbs_cert.validity in
      let (t1, t2) =
        Asn.Time.(to_posix_time not_before, to_posix_time not_after) in
      t1 <= now && now <= t2

  let version_matches_extensions { asn = cert ; _ } =
    let tbs = cert.tbs_cert in
    match tbs.version, tbs.extensions with
    | (`V1 | `V2), [] -> true
    | (`V1 | `V2), _  -> false
    | `V3        , _  -> true

  let validate_path_len pathlen { asn = cert ; _ } =
    (* X509 V1/V2 certificates do not contain X509v3 extensions! *)
    (* thus, we cannot check the path length. this will only ever happen for trust anchors: *)
    (* intermediate CAs are checked by is_cert_valid, which checks that the CA extensions are there *)
    (* whereas trust anchor are ok with getting V1/2 certificates *)
    (* TODO: make it configurable whether to accept V1/2 certificates at all *)
    let open Extension in
    match cert.tbs_cert.version, extn_basic_constr cert with
    | (`V1 | `V2), _                                   -> true
    | `V3, Some (_ , Basic_constraints (true, None))   -> true
    | `V3, Some (_ , Basic_constraints (true, Some n)) -> n >= pathlen
    | _                                                -> false

  let cacert_fingerprints =
    List.map
      Uncommon.Cs.of_hex
      [ "FF2A65CFF1149C7430101E0F65A07EC19183A3B633EF4A6510890DAD18316B3A" (* class 1 from 2003 *) ;
        "4EDDE9E55CA453B388887CAA25D5C5C5BCCF2891D73B87495808293D5FAC83C8" (* class 3 from 2011 *) ;
      ]

  let is_cacert raw =
    let fp = Hash.digest `SHA256 raw in
    List.exists (fun x -> Uncommon.Cs.equal x fp) cacert_fingerprints

  let validate_ca_extensions { asn ; raw } =
    let cert = asn in
    let open Extension in
    (* comments from RFC5280 *)
    (* 4.2.1.9 Basic Constraints *)
    (* Conforming CAs MUST include this extension in all CA certificates used *)
    (* to validate digital signatures on certificates and MUST mark the *)
    (* extension as critical in such certificates *)
    (* unfortunately, there are 8 CA certs (including the one which
       signed google.com) which are _NOT_ marked as critical *)
    ( match extn_basic_constr cert with
      | Some (_ , Basic_constraints (true, _))   -> true
      | _                                        -> false ) &&

    (* 4.2.1.3 Key Usage *)
    (* Conforming CAs MUST include key usage extension *)
    (* CA Cert (cacert.org) does not *)
    ( match extn_key_usage cert with
      (* When present, conforming CAs SHOULD mark this extension as critical *)
      (* yeah, you wish... *)
      | Some (_, Key_usage usage) -> List.mem `Key_cert_sign usage
      | None when is_cacert raw   -> true (* CA Cert does not include any key usage extensions *)
      | _                         -> false ) &&

    (* if we require this, we cannot talk to github.com
       (* 4.2.1.12.  Extended Key Usage
       If a certificate contains both a key usage extension and an extended
       key usage extension, then both extensions MUST be processed
       independently and the certificate MUST only be used for a purpose
       consistent with both extensions.  If there is no purpose consistent
       with both extensions, then the certificate MUST NOT be used for any
       purpose. *)
       ( match extn_ext_key_usage cert with
       | Some (_, Ext_key_usage usages) -> List.mem Any usages
       | _                              -> true ) &&
    *)

    (* Name Constraints - name constraints should match servername *)

    (* check criticality *)
    List.for_all (function
        | (true, Key_usage _)         -> true
        | (true, Basic_constraints _) -> true
        | (crit, _)                   -> not crit )
      cert.tbs_cert.extensions

  let validate_server_extensions { asn = cert ; _ } =
    let open Extension in
    List.for_all (function
        | (_, Basic_constraints (true, _))  -> false
        | (_, Basic_constraints (false, _)) -> true
        | (_, Key_usage _)                  -> true
        | (_, Ext_key_usage _)              -> true
        | (_, Subject_alt_name _)           -> true
        | (c, Policies ps)                  -> not c || List.mem `Any ps
        (* we've to deal with _all_ extensions marked critical! *)
        | (crit, _)                         -> not crit )
      cert.tbs_cert.extensions

  let is_cert_valid now cert =
    match
      validate_time now cert,
      version_matches_extensions cert,
      validate_ca_extensions cert
    with
    | (true, true, true) -> success
    | (false, _, _)      -> fail (`CertificateExpired cert)
    | (_, false, _)      -> fail (`InvalidVersion cert)
    | (_, _, false)      -> fail (`InvalidExtensions cert)

  let valid_trust_anchor_extensions cert =
    match cert.asn.tbs_cert.version with
    | `V1 | `V2 -> true
    | `V3       -> validate_ca_extensions cert

  let is_ca_cert_valid now cert =
    match
      is_self_signed cert,
      version_matches_extensions cert,
      validate_signature cert cert,
      validate_time now cert,
      valid_trust_anchor_extensions cert
    with
    | (true, true, true, true, true) -> success
    | (false, _, _, _, _)            -> fail (`InvalidCA cert)
    | (_, false, _, _, _)            -> fail (`InvalidVersion cert)
    | (_, _, false, _, _)            -> fail (`InvalidSignature (cert, cert))
    | (_, _, _, false, _)            -> fail (`CertificateExpired cert)
    | (_, _, _, _, false)            -> fail (`InvalidExtensions cert)

  let is_server_cert_valid ?host now cert =
    match
      validate_time now cert,
      maybe_validate_hostname cert host,
      version_matches_extensions cert,
      validate_server_extensions cert
    with
    | (true, true, true, true) -> success
    | (false, _, _, _)         -> fail (`CertificateExpired cert)
    | (_, false, _, _)         -> fail (`InvalidServerName cert)
    | (_, _, false, _)         -> fail (`InvalidVersion cert)
    | (_, _, _, false)         -> fail (`InvalidServerExtensions cert)

  let ext_authority_matches_subject { asn = trusted ; _ } { asn = cert ; _ } =
    let open Extension in
    match
      extn_authority_key_id cert, extn_subject_key_id trusted
    with
    | (_, None) | (None, _)                      -> true (* not mandatory *)
    | Some (_, Authority_key_id (Some auth, _, _)),
      Some (_, Subject_key_id au)                -> Uncommon.Cs.equal auth au
    (* TODO: check exact rules in RFC5280 *)
    | Some (_, Authority_key_id (None, _, _)), _ -> true (* not mandatory *)
    | _, _                                       -> false

  let signs pathlen trusted cert =
    match
      issuer_matches_subject trusted cert,
      ext_authority_matches_subject trusted cert,
      validate_signature trusted cert,
      validate_path_len pathlen trusted
    with
    | (true, true, true, true) -> success
    | (false, _, _, _)         -> fail (`IssuerSubjectMismatch (trusted, cert))
    | (_, false, _, _)         -> fail (`AuthorityKeyIdSubjectKeyIdMismatch (trusted, cert))
    | (_, _, false, _)         -> fail (`InvalidSignature (trusted, cert))
    | (_, _, _, false)         -> fail (`InvalidPathlen trusted)

  let issuer trusted cert =
    List.filter (fun p -> issuer_matches_subject p cert) trusted

  let rec validate_anchors pathlen cert = function
    | []    -> fail `NoTrustAnchor
    | x::xs -> match signs pathlen x cert with
      | Ok _    -> Ok (Some x)
      | Error _ -> validate_anchors pathlen cert xs

  let verify_chain ?host ?time (server, certs) =
    let rec climb pathlen cert = function
      | super :: certs ->
        signs pathlen super cert >>= fun () ->
        climb (succ pathlen) super certs
      | [] -> Ok (pathlen, cert)
    in
    is_server_cert_valid ?host time server >>= fun () ->
    iter_m (is_cert_valid time) certs      >>= fun () ->
    climb 0 server certs

  type result = [
    | `Ok   of t option
    | `Fail of validation_error
  ]

  let verify_chain_of_trust ?host ?time ~anchors = function
    | [] -> `Fail `EmptyCertificateChain
    | server :: certs ->
      let res =
        verify_chain ?host ?time (server, certs) >>= fun (pathlen, cert) ->
        match List.filter (validate_time time) (issuer anchors cert) with
        | [] when is_self_signed cert -> fail (`SelfSigned cert)
        | []                          -> fail `NoTrustAnchor
        | anchors                     -> validate_anchors pathlen cert anchors
      in
      lower res

  let valid_cas ?time cas =
    List.filter
      (fun cert -> is_success @@ is_ca_cert_valid time cert)
      cas

  let trust_fingerprint ?host ?time ~hash ~fingerprints =
    function
    | [] -> `Fail `EmptyCertificateChain
    | server::_ ->
      let verify_fingerprint server fingerprints =
        let cert_fp = Hash.digest hash server.raw in
        (try Ok (List.find (fun (_, fp) -> Uncommon.Cs.equal fp cert_fp) fingerprints)
         with Not_found -> fail (`InvalidFingerprint server)) >>= fun (name, _) ->
        if maybe_validate_hostname server (Some (`Wildcard name)) then
          Ok None
        else
          fail (`ServerNameNotPresent server)
      in

      let res =
        match validate_time time server, maybe_validate_hostname server host with
        | true , true  -> verify_fingerprint server fingerprints
        | false, _     -> fail (`CertificateExpired server)
        | _    , false -> fail (`InvalidServerName server)
      in
      lower res

end

(* RFC5246 says 'root certificate authority MAY be omitted' *)

(* TODO: how to deal with
    2.16.840.1.113730.1.1 - Netscape certificate type
    2.16.840.1.113730.1.12 - SSL server name
    2.16.840.1.113730.1.13 - Netscape certificate comment *)

(* stuff from 4366 (TLS extensions):
  - root CAs
  - client cert url *)

(* Future TODO Certificate Revocation Lists and OCSP (RFC6520)
2.16.840.1.113730.1.2 - Base URL
2.16.840.1.113730.1.3 - Revocation URL
2.16.840.1.113730.1.4 - CA Revocation URL
2.16.840.1.113730.1.7 - Renewal URL
2.16.840.1.113730.1.8 - Netscape CA policy URL

2.5.4.38 - id-at-authorityRevocationList
2.5.4.39 - id-at-certificateRevocationList

2.5.29.20 - CRL Number
2.5.29.21 - reason code
2.5.29.27 - Delta CRL indicator
2.5.29.28 - Issuing Distribution Point
2.5.29.31 - CRL Distribution Points
2.5.29.46 - FreshestCRL

do not forget about 'authority information access' (private internet extension -- 4.2.2 of 5280) *)

(* Future TODO: Policies
2.5.29.32 - Certificate Policies
2.5.29.33 - Policy Mappings
2.5.29.36 - Policy Constraints
 *)

(* Future TODO: anything with subject_id and issuer_id ? seems to be not used by anybody *)
