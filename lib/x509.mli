(** Modules for X509 (RFC5280) handling *)

module Certificate : sig
  (** Certificate validation as described in RFC5280 and RFC6125. *)

  (** abstract type of a certificate *)
  type certificate with sexp

  (** strict or wildcard matching of a server name *)
  type host = [ `Strict of string | `Wildcard of string ]

  (** [parse cstruct] is [certificate option] where the [cstruct] is parsed to a high-level [certificate] or failure *)
  val parse       : Cstruct.t -> certificate option

  (** [cs_of_cert certificate] is [cstruct] the binary representation of the [certificate]. *)
  val cs_of_cert  : certificate -> Cstruct.t

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

  (** variant of key usages *)
  type key_usage = [
    | `Digital_signature
    | `Content_commitment
    | `Key_encipherment
    | `Data_encipherment
    | `Key_agreement
    | `Key_cert_sign
    | `CRL_sign
    | `Encipher_only
    | `Decipher_only
  ]

  (** [supports_usage ?not_present certificate key_usage] is [result], whether the [certificate] supports the requested [key_usage] *)
  val supports_usage          : ?not_present:bool -> certificate -> key_usage -> bool

  (** variant of extended key usages *)
  type extended_key_usage = [
    | `Any
    | `Server_auth
    | `Client_auth
    | `Code_signing
    | `Email_protection
    | `Ipsec_end
    | `Ipsec_tunnel
    | `Ipsec_user
    | `Time_stamping
    | `Ocsp_signing
    | `Other of Asn.OID.t
  ]

  (** [supports_extended_usage certificate extended_key_usage] is [result], whether the [certificate] supports the requested [extended_key_usage] *)
  val supports_extended_usage : ?not_present:bool -> certificate -> extended_key_usage -> bool

  (** [cert_hostnames certficate] is [hostnames], the list of hostnames mentioned in the [certifcate] *)
  val cert_hostnames      : certificate -> string list

  (** [supports_hostname certificate host] is [result], whether the [certificate] is valid for the requested [host] *)
  val supports_hostname   : certificate -> host -> bool

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

  (** *)
  val pkcs1_digest_info_of_cstruct : Cstruct.t -> (Nocrypto.Hash.hash * Cstruct.t) option

  val pkcs1_digest_info_to_cstruct : Nocrypto.Hash.hash * Cstruct.t -> Cstruct.t
end


module Parser : sig
  module Cs : sig
    val hex_to_cs : string -> Cstruct.t
    val dotted_hex_to_cs : string -> Cstruct.t
  end

  (** A parser for PEM files *)
  module Pem : sig
    (** [parse pem] is [(name * data) list], in which the [pem] is parsed into its components, each surrounded by [BEGIN name] and [END name]. The actual [data] is base64 decoded. *)
    val parse : Cstruct.t -> (string * Cstruct.t) list
  end

  (** A parser for X509 certificates in PEM format *)
  module Cert : sig
    (** The type of a certificate  *)
    type t = Certificate.certificate

    (** [of_pem_cstruct pem] is [t list], where all certificates of the [pem] are extracted *)
    val of_pem_cstruct  : Cstruct.t -> t list

    (** [of_pem_cstruct1 pem] is [t], where the single certificate of the [pem] is extracted *)
    val of_pem_cstruct1 : Cstruct.t -> t
  end

  (** A parser for unencrypted private RSA keys certificates in PEM format *)
  module PK : sig
    (** The private RSA key type *)
    type t = Nocrypto.Rsa.priv

    (** [of_pem_cstruct pem] is [t list], where all private keys of [pem] are extracted *)
    val of_pem_cstruct  : Cstruct.t -> t list

    (** [of_pem_cstruct1 pem] is [t], where the private key of [pem] is extracted *)
    val of_pem_cstruct1 : Cstruct.t -> t
  end
end

(** The authenticator for a certificate chain *)
module Authenticator : sig

  (** Authentication decision, either [`Ok] with trust anchor or [`Fail] with a reason *)
  type res = [
    | `Ok   of Certificate.certificate option
    | `Fail of Certificate.certificate_failure
  ]

  (** An authenticator is a function taking a hostname and a certificate stack
      to an authentication decision. *)
  type t = ?host:Certificate.host -> Certificate.certificate list -> res
    with sexp

  (** [chain_of_trust ?time trust_anchors] is [authenticator], which uses the given [time] and set of [trust_anchors] to verify the certificate chain. This is an implementation of the algorithm in RFC5280. *)
  val chain_of_trust : ?time:float -> Parser.Cert.t list -> t

  (** [server_fingerprint ?time hash fingerprints] is an [authenticator] which uses the given [time] to verify the certificate chain - if successful the [hash] of the server certificate is checked against the entry in the fingerprint list. *)
  val server_fingerprint : ?time:float -> hash:Nocrypto.Hash.hash -> fingerprints:(string * Cstruct.t) list -> t

  (** [null] is [authenticator], which always returns [`Ok]. For testing purposes only. *)
  val null : t
end
