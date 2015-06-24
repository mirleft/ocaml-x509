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

let component_to_string = function
  | `CN s -> "CN=" ^ s
  | `Serialnumber s -> "Serialnumber=" ^ s
  | `C s -> "C=" ^ s
  | `L s -> "L=" ^ s
  | `SP s -> "SP=" ^ s
  | `O s -> "O=" ^ s
  | `OU s -> "OU=" ^ s
  | `T s -> "T=" ^ s
  | `DNQ s -> "DNQ=" ^ s
  | `Mail s -> "Mail=" ^ s
  | `DC s -> "DC=" ^ s
  | `Given_name s -> "Given_name=" ^ s
  | `Surname s -> "Surname=" ^ s
  | `Initials s -> "Initials=" ^ s
  | `Pseudonym s -> "Pseudonym=" ^ s
  | `Generation s -> "Generation=" ^ s
  | `Other (oid, s) -> Asn.OID.to_string oid ^ "=" ^ s

let dn_to_string dn = String.concat "/" (List.map component_to_string dn)

type public_key = [
  | `RSA    of Nocrypto.Rsa.pub
  | `EC_pub of Asn.OID.t
]

type private_key = [ `RSA of Nocrypto.Rsa.priv ]

type keytype = [ `RSA | `EC of Asn.OID.t ]

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
  | `Other of Asn.OID.t
]

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

type authority_key_id = Cstruct.t option * general_name list * Z.t option

type priv_key_usage_period = [
  | `Interval   of Asn.Time.t * Asn.Time.t
  | `Not_after  of Asn.Time.t
  | `Not_before of Asn.Time.t
]

type name_constraint = (general_name * int * int option) list
type name_constraints = name_constraint * name_constraint

type cert_policy = [ `Any | `Something of Asn.OID.t ]

type extension = [
  | `Unsupported       of Asn.OID.t * Cstruct.t
  | `Subject_alt_name  of general_name list
  | `Authority_key_id  of authority_key_id
  | `Subject_key_id    of Cstruct.t
  | `Issuer_alt_name   of general_name list
  | `Key_usage         of key_usage list
  | `Ext_key_usage     of extended_key_usage list
  | `Basic_constraints of (bool * int option)
  | `Priv_key_period   of priv_key_usage_period
  | `Name_constraints  of name_constraints
  | `Policies          of cert_policy list
]

type request_info_extensions = [
  | `Password of string
  | `Name of string
  | `Extensions of (bool * extension) list
]

