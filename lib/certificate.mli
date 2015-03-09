(** Certificate validation as described in RFC5280 and RFC6125. *)

(** abstract type of a certificate *)
type certificate with sexp

(** strict or wildcard matching of a server name *)
type host = [ `Strict of string | `Wildcard of string ]

(** [parse cstruct] is [certificate option] where the [cstruct] is parsed to a high-level [certificate] or failure *)
val parse       : Cstruct.t -> certificate option

(** [cs_of_cert certificate] is [cstruct] the binary representation of the [certificate]. *)
val cs_of_cert  : certificate -> Cstruct.t

(** [asn_of_cert certificate] is [asn] the ASN.1 representation of the [certificate]. *)
val asn_of_cert : certificate -> Asn_grammars.certificate

(** possible failures while validating a certificate chain *)
type certificate_failure =
  | InvalidSignature of certificate * certificate
  | CertificateExpired of certificate
  | InvalidExtensions of certificate
  | InvalidVersion of certificate
  | InvalidPathlen of certificate
  | SelfSigned of certificate
  | NoTrustAnchor
  | InvalidServerExtensions of certificate
  | InvalidServerName of certificate
  | InvalidCA of certificate
  | IssuerSubjectMismatch of certificate * certificate
  | AuthorityKeyIdSubjectKeyIdMismatch of certificate * certificate
  | NoServerName
  | ServerNameNotPresent
  | InvalidFingerprint of certificate
  | NoCertificate
with sexp

(** variant of public keys *)
type pubkey = [ `RSA of Nocrypto.Rsa.pub ]

(** [cert_pubkey certificate] is [pubkey], the public key of the [certificate] *)
val cert_pubkey         : certificate -> pubkey option

(** variant of different public key types of a certificate *)
type key_type = [ `RSA | `DH | `ECDH | `ECDSA ]

(** [supports_keytype certificate key_type] is [result], whether public key of the [certificate] matches the given [key_type] *)
val supports_keytype        : certificate -> key_type -> bool

(** [supports_usage certificate key_usage] is [result], whether the [certificate] supports the requested [key_usage] *)
val supports_usage          : certificate -> Asn_grammars.Extension.key_usage -> bool

(** [supports_extended_usage certificate extended_key_usage] is [result], whether the [certificate] supports the requested [extended_key_usage] *)
val supports_extended_usage : certificate -> Asn_grammars.Extension.extended_key_usage -> bool

(** [cert_hostnames certficate] is [hostnames], the list of hostnames mentioned in the [certifcate] *)
val cert_hostnames      : certificate -> string list

(** [wildcard_matches hostname certificate] is [result], depending on whether the certificate contains a wildcard name which the hostname matches. *)
val wildcard_matches    : string -> certificate -> bool


(** [verify_chain_of_trust ?host ?time ~anchors certificates] is [validation_result], where the [certificates] are verified using the algorithm from RFC5280: The validity period of the given certificates is checked against the [time]. The X509v3 extensions of the [stack] are checked, then a chain of trust from some [anchors] to the server certificate is validated. Also, the server certificate is checked to contain the given [hostname] in its subject alternative name extension (or common name if subject alternative name is not present), either using wildcard or strict matching as described in RFC6125. The returned certificate is the trust anchor. *)
val verify_chain_of_trust :
  ?host:host -> ?time:float -> anchors:(certificate list) -> certificate list
  -> [ `Ok of certificate option | `Fail of certificate_failure ]

(** [trust_fingerprint ?time hash fingerprints certificates] is [validation_result], where only the head of  [certificates] is verified against the given [fingerprints] map (hostname to fingerprint). Lookup in the fingerprint list is based on the provided [host]. If no host is provided, [validation_result] is [`Fail]. *)
val trust_fingerprint :
  ?host:host -> ?time:float -> hash:Nocrypto.Hash.hash -> fingerprints:(string * Cstruct.t) list -> certificate list
  -> [ `Ok of certificate option | `Fail of certificate_failure ]

(** [valid_cas ?time certificates] is [valid_certificates] which has filtered out those certificates which validity period does not contain [time]. Furthermore, X509v3 extensions are checked (basic constraints must be true). *)
val valid_cas : ?time:float -> certificate list -> certificate list

(** [common_name_to_string certificate] is [common_name] which is the extracted common name from the subject *)
val common_name_to_string         : certificate -> string

(** [certificate_failure_to_string failure] is [failure_string] which is a string describing the [failure]. *)
val certificate_failure_to_string : certificate_failure -> string

open Sexplib
val certificate_of_sexp : Sexp.t -> certificate
val sexp_of_certificate : certificate -> Sexp.t
