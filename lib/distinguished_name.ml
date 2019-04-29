
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

type t = component list

let compare_unordered_lists cmp l1 l2 =
  let rec loop = function
    | (x::xs, y::ys) -> ( match cmp x y with 0 -> loop (xs, ys) | n -> n )
    | ([], [])       ->  0
    | ([], _ )       -> -1
    | (_ , [])       ->  1
  in
  loop List.(sort cmp l1, sort cmp l2)

(* rfc5280 section 7.1. -- we're too strict on strings and should preserve the
 * order. *)
let equal n1 n2 = compare_unordered_lists compare n1 n2 = 0

let pp ppf dn = Fmt.(list ~sep:(unit "/") pp_component) ppf dn

module Asn = struct
  open Asn.S
  open Asn_grammars

  (* ASN `Name' fragmet appears all over. *)

  (* rfc5280 section 4.1.2.4 - name components we "must" handle. *)
  (* A list of abbreviations: http://pic.dhe.ibm.com/infocenter/wmqv7/v7r1/index.jsp?topic=%2Fcom.ibm.mq.doc%2Fsy10570_.htm *)
  (* Also rfc4519. *)

  (* See rfc5280 section 4.1.2.4. *)
  let directory_name =
    let f = function | `C1 s -> s | `C2 s -> s | `C3 s -> s
                     | `C4 s -> s | `C5 s -> s | `C6 s -> s
    and g s = `C1 s in
    map f g @@
    choice6
      utf8_string printable_string
      ia5_string universal_string teletex_string bmp_string


  (* We flatten the sequence-of-set-of-tuple here into a single list.
  * This means that we can't write non-singleton sets back.
  * Does anyone need that, ever?
  *)

  let name =
    let open Registry in

    let a_f = case_of_oid_f [
      (domain_component              , fun x -> `DC           x) ;
      (X520.common_name              , fun x -> `CN           x) ;
      (X520.serial_number            , fun x -> `Serialnumber x) ;
      (X520.country_name             , fun x -> `C            x) ;
      (X520.locality_name            , fun x -> `L            x) ;
      (X520.state_or_province_name   , fun x -> `SP           x) ;
      (X520.organization_name        , fun x -> `O            x) ;
      (X520.organizational_unit_name , fun x -> `OU           x) ;
      (X520.title                    , fun x -> `T            x) ;
      (X520.dn_qualifier             , fun x -> `DNQ          x) ;
      (PKCS9.email                   , fun x -> `Mail         x) ;
      (X520.given_name               , fun x -> `Given_name   x) ;
      (X520.surname                  , fun x -> `Surname      x) ;
      (X520.initials                 , fun x -> `Initials     x) ;
      (X520.pseudonym                , fun x -> `Pseudonym    x) ;
      (X520.generation_qualifier     , fun x -> `Generation   x) ]
      ~default:(fun oid x -> `Other (oid, x))

    and a_g = function
      | `DC           x   -> (domain_component              , x )
      | `CN           x   -> (X520.common_name              , x )
      | `Serialnumber x   -> (X520.serial_number            , x )
      | `C            x   -> (X520.country_name             , x )
      | `L            x   -> (X520.locality_name            , x )
      | `SP           x   -> (X520.state_or_province_name   , x )
      | `O            x   -> (X520.organization_name        , x )
      | `OU           x   -> (X520.organizational_unit_name , x )
      | `T            x   -> (X520.title                    , x )
      | `DNQ          x   -> (X520.dn_qualifier             , x )
      | `Mail         x   -> (PKCS9.email                   , x )
      | `Given_name   x   -> (X520.given_name               , x )
      | `Surname      x   -> (X520.surname                  , x )
      | `Initials     x   -> (X520.initials                 , x )
      | `Pseudonym    x   -> (X520.pseudonym                , x )
      | `Generation   x   -> (X520.generation_qualifier     , x )
      | `Other (oid,  x ) -> (oid                           , x )
    in

    let attribute_tv =
      map a_f a_g @@
      sequence2
        (required ~label:"attr type"  oid)
        (* This is ANY according to rfc5280. *)
        (required ~label:"attr value" directory_name) in
    let rd_name      = set_of attribute_tv in
    let rdn_sequence =
      map List.concat (List.map (fun x -> [x]))
      @@
      sequence_of rd_name
    in
    rdn_sequence (* A vacuous choice, in the standard. *)

  let (name_of_cstruct, name_to_cstruct) =
    projections_of Asn.der name
end

let decode_der = Asn.name_of_cstruct

let encode_der = Asn.name_to_cstruct
