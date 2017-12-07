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

  | `Other        of Asn.oid * string
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
  | `Other (oid, s) -> Format.asprintf "%a=%s" Asn.OID.pp oid s

let distinguished_name_to_string dn =
  Astring.String.concat ~sep:"/" (List.map component_to_string dn)

type public_key = [
  | `RSA    of Nocrypto.Rsa.pub
  | `EC_pub of Asn.oid
]

type private_key = [ `RSA of Nocrypto.Rsa.priv ]

type key_type = [ `RSA | `EC of Asn.oid ]

