open Sexplib.Conv
open Nocrypto
open Astring

open X509_common
open Asn_grammars

include X509_types

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

let fingerprint hash cert = Hash.digest hash cert.raw

let issuer { asn ; _ } = asn.tbs_cert.issuer

let subject { asn ; _ } = asn.tbs_cert.subject

let serial { asn ; _ } = asn.tbs_cert.serial

let validity { asn ; _ } = asn.tbs_cert.validity

let parse_certificate cs =
  match certificate_of_cstruct cs with
  | None     -> None
  | Some asn -> Some { asn ; raw = cs }

let cs_of_cert { raw ; _ } = raw

(* XXX Revisit this - would be lovely to dump the full ASN tree. *)
let t_of_sexp _ = failwith "can't parse cert from sexps"

let to_hex cs =
  let i_to_h i idx s =
    let v_to_h = function
      | x when x < 10 -> char_of_int (x + 48)
      | x -> char_of_int (x + 55)
    in
    let high = (0xf0 land i) lsr 4
    and low = 0x0f land i
    in
    Bytes.set s idx (v_to_h high) ;
    Bytes.set s (succ idx) (v_to_h low)
  in
  let s = Bytes.make (Cstruct.len cs * 3 - 1) ':' in
  for i = 0 to pred (Cstruct.len cs) do
    i_to_h (Cstruct.get_uint8 cs i) (i * 3) s
  done ;
  Bytes.to_string s

let sexp_of_t cert = Sexplib.Sexp.List
    [ Sexplib.Sexp.Atom "CERTIFICATE" ;
      Sexplib.Sexp.Atom (to_hex (fingerprint `SHA256 cert)) ]

let key_id = function
  | `RSA p -> Hash.digest `SHA1 (PK.rsa_public_to_cstruct p)
  | `EC_pub _ -> invalid_arg "ECDSA not implemented"

let key_fingerprint ?(hash = `SHA256) pub =
  Hash.digest hash (Asn_grammars.PK.pub_info_to_cstruct pub)

let private_key_to_keytype = function
  | `RSA _ -> `RSA

let public_key { asn = cert ; _ } = cert.tbs_cert.pk_info

let supports_keytype c t =
  match public_key c, t with
  | (`RSA _), `RSA -> true
  | _              -> false

let subject_common_name cert =
  List_ext.map_find cert.tbs_cert.subject
           ~f:(function `CN n -> Some n | _ -> None)

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
let hostnames { asn = cert ; _ } : string list =
  match extn_subject_alt_name cert, subject_common_name cert with
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

type host = [ `Strict of string | `Wildcard of string ] [@@deriving sexp]

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
  | `Strict name   -> List.mem (String.Ascii.lowercase name) (hostnames cert)
  | `Wildcard name -> let name = String.Ascii.lowercase name in
                             List.mem name (hostnames cert) ||
                               wildcard_matches name cert

let maybe_validate_hostname cert = function
  | None   -> true
  | Some x -> supports_hostname cert x

let issuer_matches_subject { asn = parent ; _ } { asn = cert ; _ } =
  Name.equal parent.tbs_cert.subject cert.tbs_cert.issuer

let is_self_signed cert = issuer_matches_subject cert cert

let validate_raw_signature raw signature_algo signature_val pk_info =
  match pk_info with
  | `RSA issuing_key ->
    ( match Rsa.PKCS1.sig_decode ~key:issuing_key signature_val with
      | None           -> false
      | Some signature ->
        match
          pkcs1_digest_info_of_cstruct signature,
          Algorithm.to_signature_algorithm signature_algo
        with
        | Some (algo, hash), Some (`RSA, h) when h = algo ->
          Cstruct.equal hash (Hash.digest algo raw)
        | _ -> false )
  | _ -> false

(* XXX should return the tbs_cert blob from the parser, this is insane *)
let raw_cert_hack raw signature =
  let siglen = Cstruct.len signature in
  let off    = if siglen > 128 then 1 else 0 in
  let snd    = Cstruct.get_uint8 raw 1 in
  let lenl   = 2 + if 0x80 land snd = 0 then 0 else 0x7F land snd in
  Cstruct.(sub raw lenl (len raw - (siglen + lenl + 19 + off)))

let validate_signature { asn = trusted ; _ } cert =
  let tbs_raw = raw_cert_hack cert.raw cert.asn.signature_val in
  validate_raw_signature tbs_raw cert.asn.signature_algo cert.asn.signature_val trusted.tbs_cert.pk_info

let validate_time time { asn = cert ; _ } =
  match time with
  | None     -> true
  | Some now ->
    let (not_before, not_after) = cert.tbs_cert.validity in
    Ptime.(is_later ~than:not_before now && is_earlier ~than:not_after now)

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
  match cert.tbs_cert.version, extn_basic_constr cert with
  | (`V1 | `V2), _                                    -> true
  | `V3, Some (_ , `Basic_constraints (true, None))   -> true
  | `V3, Some (_ , `Basic_constraints (true, Some n)) -> n >= pathlen
  | _                                                 -> false

let validate_ca_extensions { asn = cert ; _ } =
  (* comments from RFC5280 *)
  (* 4.2.1.9 Basic Constraints *)
  (* Conforming CAs MUST include this extension in all CA certificates used *)
  (* to validate digital signatures on certificates and MUST mark the *)
  (* extension as critical in such certificates *)
  (* unfortunately, there are 8 CA certs (including the one which
     signed google.com) which are _NOT_ marked as critical *)
  ( match extn_basic_constr cert with
    | Some (_ , `Basic_constraints (true, _)) -> true
    | _                                       -> false ) &&

  (* 4.2.1.3 Key Usage *)
  (* Conforming CAs MUST include key usage extension *)
  (* CA Cert (cacert.org) does not *)
  ( match extn_key_usage cert with
    (* When present, conforming CAs SHOULD mark this extension as critical *)
    (* yeah, you wish... *)
    | Some (_, `Key_usage usage) -> List.mem `Key_cert_sign usage
    | _                          -> false ) &&

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
      | (true, `Key_usage _)         -> true
      | (true, `Basic_constraints _) -> true
      | (crit, _)                    -> not crit )
    cert.tbs_cert.extensions

let validate_server_extensions { asn = cert ; _ } =
  List.for_all (function
      | (_, `Basic_constraints (true, _))  -> false
      | (_, `Basic_constraints (false, _)) -> true
      | (_, `Key_usage _)                  -> true
      | (_, `Ext_key_usage _)              -> true
      | (_, `Subject_alt_name _)           -> true
      | (c, `Policies ps)                  -> not c || List.mem `Any ps
      (* we've to deal with _all_ extensions marked critical! *)
      | (c, _)                             -> not c )
    cert.tbs_cert.extensions

let valid_trust_anchor_extensions cert =
  match cert.asn.tbs_cert.version with
  | `V1 | `V2 -> true
  | `V3       -> validate_ca_extensions cert

let ext_authority_matches_subject { asn = trusted ; _ } { asn = cert ; _ } =
  match
    extn_authority_key_id cert, extn_subject_key_id trusted
  with
  | (_, None) | (None, _)                       -> true (* not mandatory *)
  | Some (_, `Authority_key_id (Some auth, _, _)),
    Some (_, `Subject_key_id au)                -> Cstruct.equal auth au
  (* TODO: check exact rules in RFC5280 *)
  | Some (_, `Authority_key_id (None, _, _)), _ -> true (* not mandatory *)
  | _, _                                        -> false


module Validation = struct
  (* t -> t list (* set *) -> t list list *)
  let rec build_paths fst rst =
    match List.filter (fun x -> Name.equal (issuer fst) (subject x)) rst with
    | [] -> [[fst]]
    | xs ->
       let tails =
         List.fold_left
           (fun acc x -> acc @ build_paths x (List.filter (fun y -> x <> y) rst))
           [[]]
           xs
       in
       List.map (fun x -> fst :: x) tails

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

  let string_of_version = function
    | `V1 -> "1"
    | `V2 -> "2"
    | `V3 -> "3"

  let expired c now =
    let now = match now with
      | None   -> "none"
      | Some t -> Ptime.to_rfc3339 ~tz_offset_s:0 t
    and fr, un = c.asn.tbs_cert.validity
    and pp = Ptime.pp_human ~tz_offset_s:0 () in
    let msg = Format.asprintf "(valid from %a until %a)" pp fr pp un in
    (msg, now)

  type ca_error = [
    | `CAIssuerSubjectMismatch of t
    | `CAInvalidVersion of t
    | `CAInvalidSelfSignature of t
    | `CACertificateExpired of t * Ptime.t option
    | `CAInvalidExtensions of t
  ] [@@deriving sexp]

  let ca_error_to_string = function
    | `CAIssuerSubjectMismatch c ->
       "invalid CA (issuer does not match subject): " ^ common_name_to_string c
    | `CAInvalidVersion c ->
       let ver = string_of_version (c.asn.tbs_cert.version) in
       "CA certificate " ^ common_name_to_string c ^ " is X.509 version " ^
         ver  ^ ", but version 3 is needed for extensions"
    | `CAInvalidExtensions c ->
       "invalid CA extensions: " ^ common_name_to_string c
    | `CAInvalidSelfSignature c ->
       let n = common_name_to_string c in
       "CA certificate " ^ n ^ " does not have a proper self-signature"
    | `CACertificateExpired (c, now) ->
       let valid, now = expired c now
       and n = common_name_to_string c
       in
       "CA certificate " ^ n ^ " is expired " ^ valid ^ ", now: " ^ now

  type leaf_validation_error = [
    | `LeafCertificateExpired of t * Ptime.t option
    | `LeafInvalidName of t * host option
    | `LeafInvalidVersion of t
    | `LeafInvalidExtensions of t
  ] [@@deriving sexp]

  type chain_validation_error = [
    | `IntermediateInvalidExtensions of t
    | `IntermediateCertificateExpired of t * Ptime.t option
    | `IntermediateInvalidVersion of t

    | `ChainIssuerSubjectMismatch of t * t
    | `ChainAuthorityKeyIdSubjectKeyIdMismatch of t * t
    | `ChainInvalidSignature of t * t
    | `ChainInvalidPathlen of t * int

    | `EmptyCertificateChain
    | `NoTrustAnchor of t
    | `Revoked of t
  ] [@@deriving sexp]

  type chain_error = [
    | `Leaf of leaf_validation_error
    | `Chain of chain_validation_error
  ] [@@deriving sexp]

  type fingerprint_validation_error = [
    | `ServerNameNotPresent of t * string
    | `NameNotInList of t
    | `InvalidFingerprint of t * Cstruct.t * Cstruct.t
  ] [@@deriving sexp]

  type validation_error = [
    | `EmptyCertificateChain
    | `InvalidChain
    | `Leaf of leaf_validation_error
    | `Fingerprint of fingerprint_validation_error
  ] [@@deriving sexp]

  let leaf_validation_error_to_string = function
    | `LeafCertificateExpired (c, now) ->
       let valid, now = expired c now in
       "certificate " ^ common_name_to_string c ^ " is expired " ^ valid ^
         ", now: " ^ now
    | `LeafInvalidName (c, n) ->
       let n = match n with
         | Some (`Wildcard s) -> "wildcard " ^ s
         | Some (`Strict s) -> s
         | None -> "none"
       in
       n ^ " is not contained in the certificate " ^ common_name_to_string c
    | `LeafInvalidVersion c ->
       let ver = string_of_version (c.asn.tbs_cert.version) in
       "certificate " ^ common_name_to_string c ^ " is X.509 version " ^ ver  ^
         ", but version 3 is needed for extensions"
    | `LeafInvalidExtensions c ->
       "invalid server extensions: " ^ common_name_to_string c

  let fingerprint_validation_error_to_string = function
    | `ServerNameNotPresent (c, n) ->
       "fingerprint matches " ^ n ^ " in the fingerprint list, which is not a" ^
         " common name of the certificate " ^ common_name_to_string c
    | `NameNotInList c ->
       "common name of the certificate, " ^ common_name_to_string c ^
         ", is not present in the fingerprint list"
    | `InvalidFingerprint (c, c_fp, fp) ->
       common_name_to_string c ^ " (fp: " ^ to_hex c_fp ^ ") does not match" ^
         " the given fingerprint " ^ to_hex fp

  let validation_error_to_string = function
    | `EmptyCertificateChain -> "provided certificate chain is empty"
    | `InvalidChain -> "invalid certificate chain"
    | `Leaf l -> leaf_validation_error_to_string l
    | `Fingerprint f -> fingerprint_validation_error_to_string f

  let chain_validation_error_to_string = function
    | `IntermediateInvalidExtensions c ->
       "invalid intermediate certificate extensions: " ^ common_name_to_string c
    | `IntermediateCertificateExpired (c, now) ->
       let valid, now = expired c now
       and n = common_name_to_string c
       in
       "Intermediate certificate " ^ n ^ " is expired " ^ valid ^ ", now: " ^ now
    | `IntermediateInvalidVersion c ->
       let ver = string_of_version (c.asn.tbs_cert.version) in
       "Intermediate certificate " ^ common_name_to_string c ^ " is X.509 version " ^
         ver  ^ ", but version 3 is needed for extensions"
    | `ChainIssuerSubjectMismatch (c, parent) ->
       "invalid chain: issuer of " ^ common_name_to_string c ^
         " does not match subject of " ^ common_name_to_string parent
    | `ChainAuthorityKeyIdSubjectKeyIdMismatch (c, parent) ->
       "invalid chain: authority key id extension of " ^ common_name_to_string c ^
         " does not match subject key id extension of " ^ common_name_to_string parent
    | `ChainInvalidSignature (c, parent) ->
       "invalid chain: the certificate " ^ common_name_to_string c ^
         " is not signed by " ^ common_name_to_string parent
    | `ChainInvalidPathlen (c, pathlen) ->
       "invalid chain: the path length of " ^ common_name_to_string c ^
         " is smaller than the required path length " ^ string_of_int pathlen
    | `EmptyCertificateChain -> "Certificate chain is empty"
    | `NoTrustAnchor c -> "No trust anchor found for " ^ common_name_to_string c
    | `Revoked c -> "Certificate " ^ common_name_to_string c ^ " is revoked"

  let chain_error_to_string = function
    | `Leaf l -> leaf_validation_error_to_string l
    | `Chain c -> chain_validation_error_to_string c

  (* TODO RFC 5280: A certificate MUST NOT include more than one
     instance of a particular extension. *)

  let is_cert_valid now cert =
    match
      validate_time now cert,
      version_matches_extensions cert,
      validate_ca_extensions cert
    with
    | (true, true, true) -> success
    | (false, _, _)      -> fail (`IntermediateCertificateExpired (cert, now))
    | (_, false, _)      -> fail (`IntermediateInvalidVersion cert)
    | (_, _, false)      -> fail (`IntermediateInvalidExtensions cert)

  let is_ca_cert_valid now cert =
    match
      is_self_signed cert,
      version_matches_extensions cert,
      validate_signature cert cert,
      validate_time now cert,
      valid_trust_anchor_extensions cert
    with
    | (true, true, true, true, true) -> success
    | (false, _, _, _, _)            -> fail (`CAIssuerSubjectMismatch cert)
    | (_, false, _, _, _)            -> fail (`CAInvalidVersion cert)
    | (_, _, false, _, _)            -> fail (`CAInvalidSelfSignature cert)
    | (_, _, _, false, _)            -> fail (`CACertificateExpired (cert, now))
    | (_, _, _, _, false)            -> fail (`CAInvalidExtensions cert)

  let valid_ca ?time cacert =
    match is_ca_cert_valid time cacert with
    | Ok () -> `Ok
    | Error e -> `Error e

  let is_server_cert_valid ?host now cert =
    match
      validate_time now cert,
      maybe_validate_hostname cert host,
      version_matches_extensions cert,
      validate_server_extensions cert
    with
    | (true, true, true, true) -> success
    | (false, _, _, _)         -> fail (`LeafCertificateExpired (cert, now))
    | (_, false, _, _)         -> fail (`LeafInvalidName (cert, host))
    | (_, _, false, _)         -> fail (`LeafInvalidVersion cert)
    | (_, _, _, false)         -> fail (`LeafInvalidExtensions cert)

  let signs pathlen trusted cert =
    match
      issuer_matches_subject trusted cert,
      ext_authority_matches_subject trusted cert,
      validate_signature trusted cert,
      validate_path_len pathlen trusted
    with
    | (true, true, true, true) -> success
    | (false, _, _, _)         -> fail (`ChainIssuerSubjectMismatch (trusted, cert))
    | (_, false, _, _)         -> fail (`ChainAuthorityKeyIdSubjectKeyIdMismatch (trusted, cert))
    | (_, _, false, _)         -> fail (`ChainInvalidSignature (trusted, cert))
    | (_, _, _, false)         -> fail (`ChainInvalidPathlen (trusted, pathlen))

  let issuer trusted cert =
    List.filter (fun p -> issuer_matches_subject p cert) trusted

  let rec validate_anchors revoked pathlen cert = function
    | []    -> fail (`NoTrustAnchor cert)
    | x::xs -> match signs pathlen x cert with
      | Ok _    -> if revoked ~issuer:x ~cert then fail (`Revoked cert) else Ok x
      | Error _ -> validate_anchors revoked pathlen cert xs

  let lift_leaf f x =
    match f x with
    | Ok () -> Ok ()
    | Error e -> Error (`Leaf e)

  let verify_single_chain ?time ?(revoked = fun ~issuer:_ ~cert:_ -> false) anchors chain =
    let rec climb pathlen = function
      | cert :: issuer :: certs ->
         is_cert_valid time issuer >>= fun () ->
         if revoked ~issuer ~cert then fail (`Revoked cert) else success >>= fun () ->
         signs pathlen issuer cert >>= fun () ->
         climb (succ pathlen) (issuer :: certs)
      | [c] ->
         let anchors = issuer anchors c in
         validate_anchors revoked pathlen c anchors
      | [] -> fail `EmptyCertificateChain
    in
    climb 0 chain

  let lift_chain f x =
    match f x with
    | Ok x -> Ok x
    | Error e -> Error (`Chain e)

  let verify_chain ?host ?time ?revoked ~anchors = function
    | [] -> `Fail (`Chain `EmptyCertificateChain)
    | server :: certs ->
       let anchors = List.filter (validate_time time) anchors in
       let res =
         lift_leaf (is_server_cert_valid ?host time) server >>= fun () ->
         lift_chain (verify_single_chain ?time ?revoked anchors) (server :: certs)
       in
       lower res

  type result = [
    | `Ok   of (t list * t) option
    | `Fail of validation_error
  ]

  let rec any_m e f = function
    | [] -> Error e
    | c::cs -> match f c with
               | Ok ta -> Ok (Some (c, ta))
               | Error _ -> any_m e f cs

  let verify_chain_of_trust ?host ?time ?revoked ~anchors = function
    | [] -> `Fail `EmptyCertificateChain
    | server :: certs ->
       let res =
         (* verify server! *)
         lift_leaf (is_server_cert_valid ?host time) server >>= fun () ->
         (* build all paths *)
         let paths = build_paths server certs
         and anchors = List.filter (validate_time time) anchors
         in
         (* exists there one which is good? *)
         any_m `InvalidChain (verify_single_chain ?time ?revoked anchors) paths
       in
       lower res

  let valid_cas ?time cas =
    List.filter
      (fun cert -> is_success @@ is_ca_cert_valid time cert)
      cas

  let fingerprint_verification ?host ?time fingerprints fp =
    function
    | [] -> `Fail `EmptyCertificateChain
    | server::_ ->
      let verify_fingerprint server fingerprints =
        let fingerprint = fp server in
        let fp_matches (_, fingerprint') = Cstruct.equal fingerprint' fingerprint in
        if List.exists fp_matches fingerprints then
          let name, _ = List.find fp_matches fingerprints in
          if maybe_validate_hostname server (Some (`Wildcard name)) then
            Ok None
          else
            fail (`Fingerprint (`ServerNameNotPresent (server, name)))
        else
          let name_matches (n, _) = supports_hostname server (`Wildcard n) in
          if List.exists name_matches fingerprints then
            let (_, fp) = List.find name_matches fingerprints in
            fail (`Fingerprint (`InvalidFingerprint (server, fingerprint, fp)))
          else
            fail (`Fingerprint (`NameNotInList server))
      in

      let res =
        match validate_time time server, maybe_validate_hostname server host with
        | true , true  -> verify_fingerprint server fingerprints
        | false, _     -> fail (`Leaf (`LeafCertificateExpired (server, time)))
        | _    , false -> fail (`Leaf (`LeafInvalidName (server, host)))
      in
      lower res

  let trust_key_fingerprint ?host ?time ~hash ~fingerprints =
    let fp cert = key_fingerprint ~hash (public_key cert) in
    fingerprint_verification ?host ?time fingerprints fp

  let trust_cert_fingerprint ?host ?time ~hash ~fingerprints =
    let fp = fingerprint hash in
    fingerprint_verification ?host ?time fingerprints fp

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

do not forget about 'authority information access' (private internet extension -- 4.2.2 of 5280) *)

(* Future TODO: Policies
2.5.29.32 - Certificate Policies
2.5.29.33 - Policy Mappings
2.5.29.36 - Policy Constraints
 *)

(* Future TODO: anything with subject_id and issuer_id ? seems to be not used by anybody *)
