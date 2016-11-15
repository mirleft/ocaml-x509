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
  | `Other of Asn.oid
]

type general_name = [
  | `Other         of (Asn.oid * string)
  | `Rfc_822       of string
  | `DNS           of string
  | `X400_address  of unit
  | `Directory     of X509_types.distinguished_name
  | `EDI_party     of (string option * string)
  | `URI           of string
  | `IP            of Cstruct.t
  | `Registered_id of Asn.oid
]

type authority_key_id = Cstruct.t option * general_name list * Z.t option

type priv_key_usage_period = [
  | `Interval   of Ptime.t * Ptime.t
  | `Not_after  of Ptime.t
  | `Not_before of Ptime.t
]

type name_constraint = (general_name * int * int option) list

type policy = [ `Any | `Something of Asn.oid ]

type t = [
  | `Unsupported       of Asn.oid * Cstruct.t
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
