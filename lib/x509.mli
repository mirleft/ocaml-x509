(** X509 encoding, validation, and name validation.

    [X509] is a module for handling X.509 certificates, as described
    in RFC5280.  X.509 describes a hierarchical public key
    infrastructure, where all trust is delegated to certificate
    authorities (CA).  The task of a CA is to sign certificate signing
    requests (transforming them into certificates) after successful
    verification that the requestor eligible (such as the owner of a
    domain name), optionally adding usage extensions, and a validity
    period.

    The public keys of trusted CAs are distributed with the software,
    or configured manually.  When an endpoint connects, it has to
    present its certificate chain, which are pairwise signed
    certificates.  This chain is verified: the signatures have to be
    valid, the last certificate must be signed by a trusted CA, the
    name has to match the expected name, all certificates must be
    valid at the current time, and the purpose of each certificate
    must match its usage.

    An X.509 certificate is an authentication token: a public key, a
    subject (server name), a validity period, optionally a purpose,
    and various other optional extensions.

    This module provides {{!Encoding} parsers and unparsers} (PEM
    encoding and Cstruct) of ASN.1 encoded X.509 certificates,
    {{!Validation} validation} of certificates, and construction of
    {{!Authenticator} authenticators}.  Name validation, as defined in
    RFC6125, is implemented.

    Missing is the handling of certificate revocation lists, online
    certificate status protocol, some X.509v3 extensions (such as
    policy and name constraints).  The only key type fully supported
    is RSA. *)

(** {1 Abstract certificate type} *)

(** The abstract type of certificates. *)
type t

(** [t_of_sexp sexp] is [certificate], the unmarshalled [sexp]. *)
val t_of_sexp : Sexplib.Sexp.t -> t

(** [sexp_of_t certificate] is [sexp], the marshalled [certificate]. *)
val sexp_of_t : t -> Sexplib.Sexp.t

(** {1 Operations on a certificate} *)

(** The polymorphic variant of public key types. *)
type key_type = [ `RSA | `EC of Asn.OID.t ]

(** [supports_keytype certificate key_type] is [result], whether public key of the [certificate] matches the given [key_type]. *)
val supports_keytype : t -> key_type -> bool

(** The polymorphic variant of public keys. *)
type pubkey = [ `RSA of Nocrypto.Rsa.pub | `EC_pub of Asn.OID.t ]

(** [cert_pubkey certificate] is [pubkey], the public key of the
    [certificate]. *)
val cert_pubkey : t -> pubkey

(** The polymorphic variant of key usages. *)
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

(** [supports_usage ?not_present certificate key_usage] is [result],
    whether the [certificate] supports the given [key_usage]. *)
val supports_usage : ?not_present:bool -> t -> key_usage -> bool

(** The polymorphic variant of extended key usages. *)
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

(** [supports_extended_usage certificate extended_key_usage] is
    [result], whether the [certificate] supports the given
    [extended_key_usage]. *)
val supports_extended_usage : ?not_present:bool -> t -> extended_key_usage -> bool

(** [cert_hostnames certficate] are [hostnames], the list of hostnames
    this [certifcate] is valid for.  Currently, these are the DNS names of
    the subject alternativ name extension, if present, or otherwise the
    singleton list containing the common name. *)
val cert_hostnames : t -> string list

(** The polymorphic variant for hostname validation. *)
type host = [ `Strict of string | `Wildcard of string ]

(** [supports_hostname certificate host] is [result], whether the
    [certificate] contains the given [host], using
    {!cert_hostnames}. *)
val supports_hostname : t -> host -> bool

(** [common_name_to_string certificate] is [common_name], the common
    name of the subject of the [certificate]. *)
val common_name_to_string : t -> string

type component = [
  | `CN           of string
  | `Serialnumber of string
  | `C            of string
  | `L            of string
  | `SP           of string
  | `O            of string
  | `OU           of string
  | `T            of string
  | `DNQ          of string
  | `Mail         of string
  | `DC           of string

  | `Given_name   of string
  | `Surname      of string
  | `Initials     of string
  | `Pseudonym    of string
  | `Generation   of string

  | `Other        of Asn.OID.t * string
]

type distinguished_name = component list

(** [distinguished_name_to_string dn] is [string], the string representation of the distinguished name. *)
val distinguished_name_to_string : distinguished_name -> string

(** [subject t] is [dn], the subject as distinguished name of the certificate. *)
val subject : t -> distinguished_name

(** [issuer t] is [dn], the issuer as distinguished name of the certificate. *)
val issuer : t -> distinguished_name


(** Certificate Authority operations *)
module CA : sig

  (** {1 Signing} *)

  (** The abstract type of a signing request. *)
  type signing_request

  (* TODO: to/from pem *)

  (** The polymorphic variant of private keys. *)
  type privkey = [ `RSA of Nocrypto.Rsa.priv ]

  (** [generate subject private] is [signing_request], the signed request. *)
  val generate : string -> privkey -> signing_request

  (* TODO: policy/config stuff: extensions to add, signature algorithm, white/blacklist of keyusage/names/... *)

  (** [sign signing_request ?digest ?valid_from ?valid_until ?serial
      ?extensions private issuer] is [certificate], the certificate
      signed with given private key and issuer; digest defaults to
      `SHA1, validity from now for a day. *)
  val sign : signing_request -> ?digest:Nocrypto.Hash.hash -> ?valid_from:Unix.tm -> ?valid_until:Unix.tm -> ?serial:Z.t -> ?extensions:(bool * Asn_grammars.Extension.t) list -> privkey -> string -> t
end

(** Validation logic: error variant and functions. *)
module Validation : sig

  (** {1 Validation} *)

  (** {2 Validation failure} *)

  (** The polymorphic variant of validation errors. *)
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
  ]

  (** [validation_error_of_sexp sexp] is [validation_error], the unmarshalled [sexp]. *)
  val validation_error_of_sexp : Sexplib.Sexp.t -> validation_error

  (** [sexp_of_validation_error validation_error] is [sexp], the marshalled [validation_error]. *)
  val sexp_of_validation_error : validation_error -> Sexplib.Sexp.t

  (** [validation_error_to_string validation_error] is [string], the string representation of the [validation_error]. *)
  val validation_error_to_string : validation_error -> string

  (** {2 Validation functions} *)

  (** The result of a validation: either success (optionally returning the used trust anchor), or failure *)
  type result = [
    | `Ok of t option
    | `Fail of validation_error
  ]

  (** [verify_chain_of_trust ?host ?time ~anchors certificates] is
      [result], where the [certificates] are verified using the
      algorithm from RFC5280: The validity period of the given
      certificates is checked against the [time].  The X509v3
      extensions of the [stack] are checked, then a chain of trust
      from some [anchors] to the server certificate is validated.  The
      path length constraints are checked.  Finally, the server
      certificate is checked to contain the given [host], using
      {!cert_hostnames}.  The returned certificate is the root of the
      chain, a member of the given list of [anchors]. *)
  val verify_chain_of_trust :
    ?host:host -> ?time:float -> anchors:(t list) -> t list -> result

  (** [trust_fingerprint ?time ~hash ~fingerprints certificates] is
      [result], the first element of [certificates] is verified
      against the given [fingerprints] map (hostname to fingerprint).
      The certificate has to be valid in the given [time].  If a
      [host] is provided, the certificate is checked for this name.
      The [`Wildcard hostname] of the fingerprint list must match the
      name in the certificate, using {!cert_hostnames}.  *)
  val trust_fingerprint :
    ?host:host -> ?time:float -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> t list -> result

  (** [valid_cas ?time certificates] is [valid_certificates], only
      those certificates whose validity period matches the given time,
      and the certificate must be eligible for acting as a CA (basic
      constraints must be true). *)
  val valid_cas : ?time:float -> t list -> t list

end

(** Authenticators of certificate chains *)
module Authenticator : sig

  (** {1 Authenticators} *)

  (** An authenticator [a] is a function taking a hostname and a
      certificate stack to an authentication decision {!Validation.result}. *)
  type a = ?host:host -> t list -> Validation.result

  (** [chain_of_trust ?time trust_anchors] is [authenticator], which
      uses the given [time] and list of [trust_anchors] to verify the
      certificate chain. This is an implementation of the algorithm
      described in RFC5280, using
      {!Validation.verify_chain_of_trust}. *)
  val chain_of_trust : ?time:float -> t list -> a

  (** [server_fingerprint ?time hash fingerprints] is an
      [authenticator] which uses the given [time] and list of
      [fingerprints] to verify the first element of the certificate
      chain, using {!Validation.trust_fingerprint}. *)
  val server_fingerprint : ?time:float -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> a

  (** [null] is [authenticator], which always returns [`Ok]. For
      testing purposes only. *)
  val null : a

  (** [a_of_sexp sexp] is [authenticator], the unmarshalled [sexp] *)
  val a_of_sexp : Sexplib.Sexp.t -> a

  (** [sexp_of_a authenticator] is [sexp], the marshalled [authenticator] *)
  val sexp_of_a : a -> Sexplib.Sexp.t
end

(** Encodings *)
module Encoding : sig

  (** {1 ASN.1 Encoding} *)

  (** [parse cstruct] is [certificate option], the ASN.1 decoded
      [certificate] or [None] *)
  val parse : Cstruct.t -> t option

  (** [cs_of_cert certificate] is [cstruct], the ASN.1 encoded
      representation of the [certificate]. *)
  val cs_of_cert  : t -> Cstruct.t

  (** [pkcs1_digest_info_of_cstruct data] is [hash, signature option],
      the hash and raw signature. *)
  val pkcs1_digest_info_of_cstruct : Cstruct.t ->
    (Nocrypto.Hash.hash * Cstruct.t) option

  (** [pkcs1_digest_info_to_cstruct (hash, signature)] is [data], the
      encoded hash and signature. *)
  val pkcs1_digest_info_to_cstruct : (Nocrypto.Hash.hash * Cstruct.t) -> Cstruct.t

  (** [rsa_public_to_cstruct pk] is [buffer], the ASN.1 encoding of the
      given public key. *)
  val rsa_public_to_cstruct : Nocrypto.Rsa.pub -> Cstruct.t

  (** [rsa_public_of_cstruct buffer] is [pubkey], the public key of
      the ASN.1 encoded buffer. *)
  val rsa_public_of_cstruct : Cstruct.t -> Nocrypto.Rsa.pub option

  (** A parser for PEM files *)
  module Pem : sig

    (** {2 PEM encoding} *)

    (** [parse pem] is [(name * data) list], in which the [pem] is
        parsed into its components, each surrounded by [BEGIN name] and
        [END name]. The actual [data] is base64 decoded. *)
    val parse : Cstruct.t -> (string * Cstruct.t) list

    (** A parser for X509 certificates in PEM format *)
    module Cert : sig

      (** {3 PEM encoded certificates} *)

      (** [of_pem_cstruct pem] is [t list], where all certificates of
          the [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> t list

      (** [of_pem_cstruct1 pem] is [t], where the single certificate
          of the [pem] is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> t

      (** [to_pem_cstruct certificates] is [pem], the pem encoded
          certificates. *)
      val to_pem_cstruct : t list -> Cstruct.t

      (** [to_pem_cstruct1 certificate] is [pem], the pem encoded
          certificate. *)
      val to_pem_cstruct1 : t -> Cstruct.t
    end

    (** A parser for public keys in PEM format *)
    module PublicKey : sig

      (** {3 PEM encoded RSA keys} *)

      (** [of_pem_cstruct pem] is [t list], where all public keys of
          [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> pubkey list

      (** [of_pem_cstruct1 pem] is [t], where the public key of [pem]
          is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> pubkey

      (** [to_pem_cstruct public_keys] is [pem], the pem encoded
          public keys. *)
      val to_pem_cstruct : pubkey list -> Cstruct.t

      (** [to_pem_cstruct1 public_key] is [pem], the pem encoded
          public key. *)
      val to_pem_cstruct1 : pubkey -> Cstruct.t
    end

    (** A parser for unencrypted private RSA keys in PEM format *)
    module PrivateKey : sig

      (** {3 PEM encoded RSA keys} *)

      (** The private RSA key type *)
      type t = Nocrypto.Rsa.priv

      (** [of_pem_cstruct pem] is [t list], where all private keys of
          [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> t list

      (** [of_pem_cstruct1 pem] is [t], where the private key of [pem]
          is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> t

      (** [to_pem_cstruct private_keys] is [pem], the pem encoded
          private keys. *)
      val to_pem_cstruct : t list -> Cstruct.t

      (** [to_pem_cstruct1 private_key] is [pem], the pem encoded
          private key. *)
      val to_pem_cstruct1 : t -> Cstruct.t
    end
  end
end

