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

let pp_component ppf = function
  | `CN s -> Fmt.pf ppf "CN=%s" s
  | `Serialnumber s -> Fmt.pf ppf "Serialnumber=%s" s
  | `C s -> Fmt.pf ppf "C=%s" s
  | `L s -> Fmt.pf ppf "L=%s" s
  | `SP s -> Fmt.pf ppf "SP=%s" s
  | `O s -> Fmt.pf ppf "O=%s" s
  | `OU s -> Fmt.pf ppf "OU=%s" s
  | `T s -> Fmt.pf ppf "T=%s" s
  | `DNQ s -> Fmt.pf ppf "DNQ=%s" s
  | `Mail s -> Fmt.pf ppf "Mail=%s" s
  | `DC s -> Fmt.pf ppf "DC=%s" s
  | `Given_name s -> Fmt.pf ppf "Given_name=%s" s
  | `Surname s -> Fmt.pf ppf "Surname=%s" s
  | `Initials s -> Fmt.pf ppf "Initials=%s" s
  | `Pseudonym s -> Fmt.pf ppf "Pseudonym=%s" s
  | `Generation s -> Fmt.pf ppf "Generation=%s" s
  | `Other (oid, s) -> Fmt.pf ppf "%a=%s" Asn.OID.pp oid s

type distinguished_name = component list

let pp_distinguished_name ppf dn =
  Fmt.(list ~sep:(unit "/") pp_component) ppf dn

type public_key = [
  | `RSA    of Nocrypto.Rsa.pub
  | `EC_pub of Asn.oid
]

type private_key = [ `RSA of Nocrypto.Rsa.priv ]

type key_type = [ `RSA | `EC of Asn.oid ]
