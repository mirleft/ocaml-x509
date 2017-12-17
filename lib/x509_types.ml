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

let component_of_string s =
  match Astring.String.cut ~sep:"=" s with
  | None -> None
  | Some (kind, value) -> match kind with
    | "CN" -> Some (`CN value)
    | "Serialnumber" -> Some (`Serialnumber value)
    | "C" -> Some (`C value)
    | "L" -> Some (`L value)
    | "SP" -> Some (`SP value)
    | "O" -> Some (`O value)
    | "OU" -> Some (`OU value)
    | "T" -> Some (`T value)
    | "DNQ" -> Some (`DNQ value)
    | "Mail" -> Some (`Mail value)
    | "DC" -> Some (`DC value)
    | "Given_name" -> Some (`Given_name value)
    | "Surname" -> Some (`Surname value)
    | "Initials" -> Some (`Initials value)
    | "Pseudonym" -> Some (`Pseudonym value)
    | "Generation" -> Some (`Generation value)
    | x -> match Asn.OID.of_string x with
      | None -> None
      | Some oid -> Some (`Other (oid, value))

type distinguished_name = component list

let distinguished_name_of_sexp = function
  | Sexplib.Sexp.List components ->
    List.fold_left (fun acc a -> match a with
        | Sexplib.Sexp.Atom str ->
          begin match component_of_string str with
            | None -> failwith ("can't parse component " ^ str)
            | Some c -> c :: acc
          end
        | _ -> failwith "invalid distinguished name: malformed component")
      [] components
  | _ -> failwith "invalid distinguished name: must be a list of components"

let sexp_of_distinguished_name dn =
  Sexplib.Sexp.List
    (List.map (fun c -> Sexplib.Sexp.Atom (component_to_string c)) dn)

let distinguished_name_to_string dn =
  Astring.String.concat ~sep:"/" (List.map component_to_string dn)

type public_key = [
  | `RSA    of Nocrypto.Rsa.pub
  | `EC_pub of Asn.oid
]

type private_key = [ `RSA of Nocrypto.Rsa.priv ]

type key_type = [ `RSA | `EC of Asn.oid ]

