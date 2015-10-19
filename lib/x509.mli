(** X509 encoding, generation, and validation.

    [X509] is a module for handling X.509 certificates, as described
    in {{:https://tools.ietf.org/html/rfc5280}RFC5280}.  X.509
    describes a hierarchical public key infrastructure, where all
    trust is delegated to certificate authorities (CA).  The task of a
    CA is to sign certificate signing requests (CSR), which turns them
    into certificates, after verification that the requestor is
    eligible.

    An X.509 certificate is an authentication token: a public key, a
    subject (e.g. server name), a validity period, optionally a
    purpose (usage), and various other optional {{!Extension}Extensions}.

    The public keys of trusted CAs are distributed with the software,
    or configured manually.  When an endpoint connects, it has to
    present its certificate chain, which are pairwise signed
    certificates.  This chain is verified: the signatures have to be
    valid, the last certificate must be signed by a trusted CA, the
    name has to match the expected name, all certificates must be
    valid at the current time, and the purpose of each certificate
    must match its usage.  An alternative validator checks that the
    hash of the server certificate matches the given hash.

    This module provides {{!Encoding}parsers and unparsers} (PEM
    encoding) of ASN.1 encoded X.509 certificates, public and private
    RSA keys ({{:http://tools.ietf.org/html/rfc5208}PKCS 8, RFC5208}),
    and certificate signing requests
    ({{:http://tools.ietf.org/html/rfc2986}PKCS 10, RFC2986}) (both
    require parts of {{:https://tools.ietf.org/html/rfc2985}PKCS9,
    RFC2985}), {{!Validation} validation} of certificates, and
    construction of {{!Authenticator} authenticators}.  Name
    validation, as defined in
    {{:https://tools.ietf.org/html/rfc6125}RFC6125}, is also
    implemented.  The {{!CA}CA} module provides functionality to
    create and sign CSR.

    Missing is the handling of certificate revocation lists, online
    certificate status protocol, some X.509v3 extensions (such as
    policy and name constraints).  The only key type supported is
    RSA. *)

(** {1 Abstract certificate type} *)

(** The abstract type of a certificate, with
    {{!Encoding.Pem.Certificate}encoding and decoding to PEM}. *)
type t

(** [t_of_sexp sexp] is [certificate], the unmarshalled [sexp]. *)
val t_of_sexp : Sexplib.Sexp.t -> t

(** [sexp_of_t certificate] is [sexp], the marshalled [certificate]. *)
val sexp_of_t : t -> Sexplib.Sexp.t

(** {1 Basic operations on a certificate} *)

(** The polymorphic variant of public key types. *)
type key_type = [ `RSA | `EC of Asn.OID.t ]

(** [supports_keytype certificate key_type] is [result], whether public key of the [certificate] matches the given [key_type]. *)
val supports_keytype : t -> key_type -> bool

(** The polymorphic variant of public keys, with
    {{:http://tools.ietf.org/html/rfc5208}PKCS 8}
    {{!Encoding.Pem.Public_key}encoding and decoding to PEM}. *)
type public_key = [ `RSA of Nocrypto.Rsa.pub | `EC_pub of Asn.OID.t ]

(** [key_id public_key] is [result], the 160-bit [`SHA1] hash of the BIT
    STRING subjectPublicKey (excluding tag, length, and number of
    unused bits) for publicKeyInfo of [public_key].

    {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.2}RFC5280, 4.2.1.2, variant (1)} *)
val key_id: public_key -> Cstruct.t

(** [key_fingerprint ?hash public_key] is [result], the hash (by
    default SHA256) of the DER encoded public key (equivalent to
    `openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER |
    openssl dgst -HASH`).  *)
val key_fingerprint : ?hash:Nocrypto.Hash.hash -> public_key -> Cstruct.t

(** The polymorphic variant of private keys, with
    {{:http://tools.ietf.org/html/rfc5208}PKCS 8}
    {{!Encoding.Pem.Private_key}encoding and decoding to PEM}. *)
type private_key = [ `RSA of Nocrypto.Rsa.priv ]

(** [public_key certificate] is [pubkey], the public key of the
    [certificate]. *)
val public_key : t -> public_key

(** [hostnames certficate] are [hostnames], the list of hostnames this
    [certificate] is valid for.  Currently, these are the DNS names of
    the {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.6}Subject
    Alternative Name} extension, if present, or otherwise the
    singleton list containing the common name. *)
val hostnames : t -> string list

(** The polymorphic variant for hostname validation. *)
type host = [ `Strict of string | `Wildcard of string ]

(** [supports_hostname certificate host] is [result], whether the
    [certificate] contains the given [host], using
    {!hostnames}. *)
val supports_hostname : t -> host -> bool

(** [common_name_to_string certificate] is [common_name], the common
    name of the subject of the [certificate]. *)
val common_name_to_string : t -> string

(** The polymorphic variant of a distinguished name component, as
    defined in X.500. *)
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

(** A distinguished name is a list of {!component}. *)
type distinguished_name = component list

(** [distinguished_name_to_string dn] is [string], the string
    representation of the {{!distinguished_name}dn}. *)
val distinguished_name_to_string : distinguished_name -> string

(** [fingerprint hash cert] is [digest],
    the digest of [cert] using the specified [hash] algorithm *)
val fingerprint : Nocrypto.Hash.hash -> t -> Cstruct.t

(** [subject certificate] is [dn], the subject as
    {{!distinguished_name}dn} of the [certificate]. *)
val subject : t -> distinguished_name

(** [issuer certificate] is [dn], the issuer as
    {{!distinguished_name}dn} of the [certificate]. *)
val issuer : t -> distinguished_name

(** [serial certificate] is [sn], the serial number of the
    [certificate]. *)
val serial : t -> Z.t

(** X.509v3 extensions *)
module Extension : sig

  (** {1 X.509v3 extension} *)

  (** The polymorphic variant of
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.3}key
  usages}. *)
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

  (** [supports_usage ~not_present certificate key_usage] is [result],
      whether the [certificate] supports the given [key_usage]
      (defaults to [~not_present] if the certificate does not contain
      a keyUsage extension). *)
  val supports_usage : ?not_present:bool -> t -> key_usage -> bool

  (** The polymorphic variant of
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.12}extended key
  usages}. *)
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

  (** [supports_extended_usage ~not_present certificate
      extended_key_usage] is [result], whether the [certificate]
      supports the given [extended_key_usage] (defaults to
      [~not_present] if the certificate does not contain an
      extendedKeyUsage extension. *)
  val supports_extended_usage : ?not_present:bool -> t -> extended_key_usage -> bool

  (** A list of [general_name]s is the value of both
      {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.6}subjectAltName}
      and
      {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.7}IssuerAltName}
      extension. *)
  type general_name = [
    | `Other         of (Asn.OID.t * string)
    | `Rfc_822       of string
    | `DNS           of string
    | `X400_address  of unit
    | `Directory     of distinguished_name
    | `EDI_party     of (string option * string)
    | `URI           of string
    | `IP            of Cstruct.t
    | `Registered_id of Asn.OID.t
  ]

  (** The authority key identifier, as present in the
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.1}Authority Key
  Identifier} extension. *)
  type authority_key_id = Cstruct.t option * general_name list * Z.t option

  (** The private key usage period, as defined in
  {{:https://tools.ietf.org/html/rfc3280#section-4.2.1.4}RFC3280}. *)
  type priv_key_usage_period = [
    | `Interval   of Asn.Time.t * Asn.Time.t
    | `Not_after  of Asn.Time.t
    | `Not_before of Asn.Time.t
  ]

  (** Name constraints, as defined in
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.10}RFC
  5280}. *)
  type name_constraint = (general_name * int * int option) list

  (** Certificate policies, the
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.4}policy
  extension}. *)
  type policy = [ `Any | `Something of Asn.OID.t ]

  (** The polymorphic variant of
  {{:https://tools.ietf.org/html/rfc5280#section-4.2}X509v3
  extensions}. *)
  type t = [
    | `Unsupported       of Asn.OID.t * Cstruct.t
    | `Subject_alt_name  of general_name list
    | `Authority_key_id  of authority_key_id
    | `Subject_key_id    of Cstruct.t
    | `Issuer_alt_name   of general_name list
    | `Key_usage         of key_usage list
    | `Ext_key_usage     of extended_key_usage list
    | `Basic_constraints of (bool * int option)
    | `Priv_key_period   of priv_key_usage_period
    | `Name_constraints  of name_constraint * name_constraint
    | `Policies          of policy list
  ]
end

(** Certificate Authority operations *)
module CA : sig

  (** {1 Signing} *)

  (** The abstract type of a (self-signed)
  {{:https://tools.ietf.org/html/rfc2986#page-7}PKCS 10 certification
  request}, with {{!Encoding.Pem.Certificate_signing_request}encoding
  and decoding to PEM}. *)
  type signing_request

  (** The polymorphic variant of certificate request extensions, as
      defined in {{:http://tools.ietf.org/html/rfc2985}PKCS 9
      (RFC2985)}. *)
  type request_extensions = [
    | `Password of string
    | `Name of string
    | `Extensions of (bool * Extension.t) list
  ]

  (** The raw request info of a
      {{:https://tools.ietf.org/html/rfc2986#section-4}PKCS 10
      certification request info}. *)
  type request_info = {
    subject    : distinguished_name ;
    public_key : public_key ;
    extensions : request_extensions list ;
  }

  (** [info signing_request] is {!request_info}, the information
      inside the {!signing_request}. *)
  val info : signing_request -> request_info

  (** [request subject ~digest ~extensions private] creates
      [signing_request], a certification request using the given
      [subject], [digest] (defaults to [`SHA256]) and list of
      [extensions]. *)
  val request : distinguished_name -> ?digest:Nocrypto.Hash.hash -> ?extensions:request_extensions list -> private_key -> signing_request

  (** [sign signing_request ~digest ~valid_from ~valid_until ~serial
      ~extensions private issuer] creates [certificate], a signed
      certificate.  Public key and subject are taken from the
      [signing_request], the [extensions] are added to the X.509
      certificate.  The [private] key is used to sign the certificate,
      the [issuer] is recorded in the certificate.  The digest
      defaults to [`SHA256].  The [serial] defaults to a random value
      between 1 and 2^64.  Certificate version is always 3.  Please
      note that the extensions in the [signing_request] are ignored,
      you can pass them using:

{[match
  try Some (List.find (function `Extensions _ -> true | _ -> false) (info csr).extensions)
  with Not_found -> None
with
 | Some (`Extensions x) -> x
 | None -> []
]}. *)
  val sign : signing_request -> valid_from:Asn.Time.t -> valid_until:Asn.Time.t -> ?digest:Nocrypto.Hash.hash -> ?serial:Z.t -> ?extensions:(bool * Extension.t) list -> private_key -> distinguished_name -> t
end

(** Validation logic: error variant and functions. *)
module Validation : sig

  (** {1 Validation} *)

  (** {2 Validation failure} *)

  (** The polymorphic variant of validation errors. *)
  type validation_error = [
    | `InvalidSignature of t * t
    | `CertificateExpired of t * float option
    | `InvalidExtensions of t
    | `InvalidVersion of t
    | `InvalidPathlen of t * int
    | `SelfSigned of t
    | `NoTrustAnchor
    | `InvalidServerExtensions of t
    | `InvalidServerName of t * host option
    | `InvalidCA of t
    | `IssuerSubjectMismatch of t * t
    | `AuthorityKeyIdSubjectKeyIdMismatch of t * t
    | `ServerNameNotPresent of t * string
    | `InvalidFingerprint of t * Cstruct.t * Cstruct.t
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

  (** [verify_chain_of_trust ~host ~time ~anchors certificates] is
      [result], where the [certificates] are verified using the
      algorithm from
      {{:https://tools.ietf.org/html/rfc5280#section-6.1}RFC5280}: The
      validity period of the given certificates is checked against the
      [time].  The X509v3 extensions of the [stack] are checked, then
      a chain of trust from some [anchors] to the server certificate
      is validated.  The path length constraints are checked.
      Finally, the server certificate is checked to contain the given
      [host], using {!hostnames}.  The returned certificate is the
      root of the chain, a member of the given list of [anchors]. *)
  val verify_chain_of_trust :
    ?host:host -> ?time:float -> anchors:(t list) -> t list -> result

  (** [trust_cert_fingerprint ~time ~hash ~fingerprints certificates] is
      [result], the first element of [certificates] is verified
      against the given [fingerprints] map (hostname to fingerprint).
      The certificate has to be valid in the given [time].  If a
      [host] is provided, the certificate is checked for this name.
      The [`Wildcard hostname] of the fingerprint list must match the
      name in the certificate, using {!hostnames}.  *)
  val trust_cert_fingerprint :
    ?host:host -> ?time:float -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> t list -> result

  val trust_key_fingerprint :
    ?host:host -> ?time:float -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> t list -> result

  (** [valid_cas ~time certificates] is [valid_certificates], only
      those certificates whose validity period matches the given time,
      and the certificate must be eligible for acting as a CA
      (self-signed, if X.509v3, the basic constraint extension must be
      present and true, and the key usage extension must contain
      keyCertSign). *)
  val valid_cas : ?time:float -> t list -> t list

end

(** Authenticators of certificate chains *)
module Authenticator : sig

  (** {1 Authenticators} *)

  (** An authenticator [a] is a function type which takes a hostname
      and a certificate stack to an authentication decision
      {!Validation.result}. *)
  type a = ?host:host -> t list -> Validation.result

  (** [chain_of_trust ?time trust_anchors] is [authenticator], which
      uses the given [time] and list of [trust_anchors] to verify the
      certificate chain. This is an implementation of the algorithm
      described in
      {{!https://tools.ietf.org/html/rfc5280#section-6.1}RFC5280},
      using {!Validation.verify_chain_of_trust}. *)
  val chain_of_trust : ?time:float -> t list -> a

  (** [server_cert_fingerprint ~time hash fingerprints] is an
      [authenticator] which uses the given [time] and list of
      [fingerprints] to verify the first element of the certificate
      chain, using {!Validation.trust_fingerprint}. *)
  val server_cert_fingerprint : ?time:float -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> a

  val server_key_fingerprint : ?time:float -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> a

  (** [null] is [authenticator], which always returns [`Ok]. (Useful
      for testing purposes only.) *)
  val null : a

  (** [a_of_sexp sexp] is [authenticator], the unmarshalled
  [sexp].  Note: only {!null} is supported. *)
  val a_of_sexp : Sexplib.Sexp.t -> a

  (** [sexp_of_a authenticator] is [sexp], the marshalled
  [authenticator].  Note: always emits {!null}. *)
  val sexp_of_a : a -> Sexplib.Sexp.t
end

(** Encodings *)
module Encoding : sig

  (** {1 ASN.1 Encoding} *)

  (** [parse cstruct] is [certificate option], the ASN.1 decoded
      [certificate] or [None]. *)
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

  (** Parser and unparser of PEM files *)
  module Pem : sig

    (** {2 PEM encoding} *)

    (** [parse pem] is [(name * data) list], in which the [pem] is
        parsed into its components, each surrounded by [BEGIN name] and
        [END name]. The actual [data] is base64 decoded. *)
    val parse : Cstruct.t -> (string * Cstruct.t) list

    (** Decoding and encoding of
       {{:https://tools.ietf.org/html/rfc5280#section-3.1}X509
       certificates} in PEM format *)
    module Certificate : sig

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

    (** Decoding and encoding of
        {{:https://tools.ietf.org/html/rfc2986}PKCS 10 certification
        requests} in PEM format *)
    module Certificate_signing_request : sig

      (** {3 PEM encoded certificate signing requests} *)

      type t = CA.signing_request

      (** [of_pem_cstruct pem] is [t list], where all signing requests
          of the [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> t list

      (** [of_pem_cstruct1 pem] is [t], where the single signing
          request of the [pem] is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> t

      (** [to_pem_cstruct signing_requests] is [pem], the pem encoded
          signing requests. *)
      val to_pem_cstruct : t list -> Cstruct.t

      (** [to_pem_cstruct1 signing_request] is [pem], the pem encoded
          signing_request. *)
      val to_pem_cstruct1 : t -> Cstruct.t
    end

    (** Decoding and encoding of public keys in PEM format as defined
        in {{:http://tools.ietf.org/html/rfc5208}PKCS 8} *)
    module Public_key : sig

      (** {3 PEM encoded RSA keys} *)

      (** [of_pem_cstruct pem] is [t list], where all public keys of
          [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> public_key list

      (** [of_pem_cstruct1 pem] is [t], where the public key of [pem]
          is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> public_key

      (** [to_pem_cstruct public_keys] is [pem], the pem encoded
          public keys. *)
      val to_pem_cstruct : public_key list -> Cstruct.t

      (** [to_pem_cstruct1 public_key] is [pem], the pem encoded
          public key. *)
      val to_pem_cstruct1 : public_key -> Cstruct.t
    end

    (** Decoding and encoding of unencrypted private RSA keys in PEM
        format as defined in
        {{:http://tools.ietf.org/html/rfc5208}PKCS 8} *)
    module Private_key : sig

      (** {3 PEM encoded RSA keys} *)

      (** [of_pem_cstruct pem] is [t list], where all private keys of
          [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> private_key list

      (** [of_pem_cstruct1 pem] is [t], where the private key of [pem]
          is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> private_key

      (** [to_pem_cstruct private_keys] is [pem], the pem encoded
          private keys. *)
      val to_pem_cstruct : private_key list -> Cstruct.t

      (** [to_pem_cstruct1 private_key] is [pem], the pem encoded
          private key. *)
      val to_pem_cstruct1 : private_key -> Cstruct.t
    end
  end
end

