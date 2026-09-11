module Encoded_string = struct
  type encoding = [ `UTF8 | `Printable | `IA5 | `Universal | `Teletex | `BMP ]
  type directory_encoding = [ `UTF8 | `Printable | `Universal | `Teletex | `BMP ]

  type +'encoding t = {
    octets : string ;
    encoding : 'encoding ;
  }

  let of_string ~(encoding : [< encoding]) octets = { octets ; encoding }

  let encoding { encoding ; _ } = encoding
  let to_string { octets ; _ } = octets
  let compare_octets a b = String.compare a.octets b.octets

  let tag = function
    | `UTF8 -> 12
    | `Printable -> 19
    | `Teletex -> 20
    | `IA5 -> 22
    | `Universal -> 28
    | `BMP -> 30

  let compare_with_tag tag a b =
    match compare_octets a b with
    | 0 -> Int.compare (tag a.encoding) (tag b.encoding)
    | n -> n

  let compare = compare_with_tag tag

  let compare_for_matching =
    compare_with_tag (function
        | `UTF8 | `Printable -> tag `UTF8
        | encoding -> tag encoding)
end

module type Attribute_value = sig
  type encoding
  type t
  val v : ?encoding:encoding -> string -> t
  val of_encoded : encoding Encoded_string.t -> t
  val encoded : t -> encoding Encoded_string.t
  val to_string : t -> string
end

module type String_encoding = sig
  type t
  val default : t
end

module Directory_encoding = struct
  type t = Encoded_string.directory_encoding
  let default : t = `UTF8
end

module Printable_encoding = struct
  type t = [ `Printable ]
  let default = `Printable
end

module Ia5_encoding = struct
  type t = [ `IA5 ]
  let default = `IA5
end

module Make_value (Encoding : String_encoding)
  : Attribute_value with type encoding = Encoding.t = struct
  type encoding = Encoding.t
  type t = encoding Encoded_string.t

  let v ?(encoding = Encoding.default) octets = { Encoded_string.octets = octets ; encoding }
  let of_encoded value = value
  let encoded t = t
  let to_string = Encoded_string.to_string
end

module Common_name = Make_value (Directory_encoding)
module Serial_number = Make_value (Printable_encoding)
module Country_name = Make_value (Printable_encoding)
module Locality_name = Make_value (Directory_encoding)
module State_or_province_name = Make_value (Directory_encoding)
module Organization_name = Make_value (Directory_encoding)
module Organizational_unit_name = Make_value (Directory_encoding)
module Title = Make_value (Directory_encoding)
module Email_address = Make_value (Ia5_encoding)
module Personal_name = Make_value (Directory_encoding)
module Pseudonym = Make_value (Directory_encoding)
module Street_address = Make_value (Directory_encoding)
module User_id = Make_value (Directory_encoding)

let known_attribute_oids = Registry.[
    domain_component; X520.common_name; X520.serial_number; X520.country_name;
    X520.locality_name; X520.state_or_province_name; X520.organization_name;
    X520.organizational_unit_name; X520.title; X520.dn_qualifier; PKCS9.email;
    X520.given_name; X520.surname; X520.initials; X520.pseudonym;
    X520.generation_qualifier; X520.street_address; userid
  ]

module Other_attribute : sig
  type t
  val create : Asn.oid -> Encoded_string.encoding Encoded_string.t -> (t, [ `Msg of string ]) result
  val oid : t -> Asn.oid
  val value : t -> Encoded_string.encoding Encoded_string.t
end = struct
  type t = { oid : Asn.oid; value : Encoded_string.encoding Encoded_string.t }
  let create oid value =
    if List.exists (Asn.OID.equal oid) known_attribute_oids then
      Error (`Msg "recognized attribute OID requires its named constructor")
    else Ok { oid; value }
  let oid t = t.oid
  let value t = t.value
end

type attribute =
  | CN of Common_name.t
  | Serialnumber of Serial_number.t
  | C of Country_name.t
  | L of Locality_name.t
  | ST of State_or_province_name.t
  | O of Organization_name.t
  | OU of Organizational_unit_name.t
  | T of Title.t
  | DNQ of [ `Printable ] Encoded_string.t
  | Mail of Email_address.t
  | DC of [ `IA5 ] Encoded_string.t
  | Given_name of Personal_name.t
  | Surname of Personal_name.t
  | Initials of Personal_name.t
  | Pseudonym of Pseudonym.t
  | Generation of Personal_name.t
  | Street of Street_address.t
  | Userid of User_id.t
  | Other of Other_attribute.t

let attribute_value = function
  | CN value -> (Common_name.encoded value :> Encoded_string.encoding Encoded_string.t)
  | Serialnumber value -> (Serial_number.encoded value :> Encoded_string.encoding Encoded_string.t)
  | C value -> (Country_name.encoded value :> Encoded_string.encoding Encoded_string.t)
  | L value -> (Locality_name.encoded value :> Encoded_string.encoding Encoded_string.t)
  | ST value -> (State_or_province_name.encoded value :> Encoded_string.encoding Encoded_string.t)
  | O value -> (Organization_name.encoded value :> Encoded_string.encoding Encoded_string.t)
  | OU value -> (Organizational_unit_name.encoded value :> Encoded_string.encoding Encoded_string.t)
  | T value -> (Title.encoded value :> Encoded_string.encoding Encoded_string.t)
  | DNQ value -> (value :> Encoded_string.encoding Encoded_string.t)
  | Mail value -> (Email_address.encoded value :> Encoded_string.encoding Encoded_string.t)
  | DC value -> (value :> Encoded_string.encoding Encoded_string.t)
  | Given_name value | Surname value | Initials value | Generation value ->
    (Personal_name.encoded value :> Encoded_string.encoding Encoded_string.t)
  | Pseudonym value -> (Pseudonym.encoded value :> Encoded_string.encoding Encoded_string.t)
  | Street value -> (Street_address.encoded value :> Encoded_string.encoding Encoded_string.t)
  | Userid value -> (User_id.encoded value :> Encoded_string.encoding Encoded_string.t)
  | Other value -> Other_attribute.value value

(* Escaping is described in RFC4514. Escaing '=' is optional, otherwise the
 * following is minimal, using the character instead of hex where possible. *)
let pp_attribute_value ?(osf = false) () ppf s =
  let n = String.length s in
  for i = 0 to n - 1 do
    match s.[i] with
    | '#' when i = 0 -> Fmt.string ppf "\\#"
    | ' ' when i = 0 || i = n - 1 -> Fmt.string ppf "\\ "
    | ',' when not osf -> Fmt.string ppf "\\,"
    | ';' when not osf -> Fmt.string ppf "\\;"
    | '/' when osf -> Fmt.string ppf "\\/"
    | '"' | '+' | '<' | '=' | '>' | '\\' as c -> Fmt.pf ppf "\\%c" c
    | '\x00' -> Fmt.string ppf "\\00"
    | c -> Fmt.char ppf c
  done

let pp_string_hex ppf s =
  for i = 0 to String.length s - 1 do
    Fmt.pf ppf "%02x" (Char.code s.[i])
  done

let pp_attribute ?osf ?(ava_equal = Fmt.any "=") () ppf attr =
  let value = Encoded_string.to_string (attribute_value attr) in
  let aux a = Fmt.pf ppf "%s%a%a" a ava_equal () (pp_attribute_value ?osf ()) value in
  match attr with
  | CN _ -> aux "CN"
  | Serialnumber _ -> aux "Serialnumber"
  | C _ -> aux "C"
  | L _ -> aux "L"
  | ST _ -> aux "ST"
  | O _ -> aux "O"
  | OU _ -> aux "OU"
  | T _ -> aux "T"
  | DNQ _ -> aux "DNQ"
  | Mail _ -> aux "Mail"
  | DC _ -> aux "DC"
  | Given_name _ -> aux "Given_name"
  | Surname _ -> aux "Surname"
  | Initials _ -> aux "Initials"
  | Pseudonym _ -> aux "Pseudonym"
  | Generation _ -> aux "Generation"
  | Street _ -> aux "Street"
  | Userid _ -> aux "UID"
  | Other other ->
    Fmt.pf ppf "%a%a#%a" Asn.OID.pp (Other_attribute.oid other) ava_equal () pp_string_hex value

let compare_attribute compare_value t t' =
  let compare_contents () = compare_value (attribute_value t) (attribute_value t') in
  match t, t' with
  | CN _, CN _ -> compare_contents ()
  | CN _, _ -> -1 | _, CN _ -> 1
  | Serialnumber _, Serialnumber _ -> compare_contents ()
  | Serialnumber _, _ -> -1 | _, Serialnumber _ -> 1
  | C _, C _ -> compare_contents ()
  | C _, _ -> -1 | _, C _ -> 1
  | L _, L _ -> compare_contents ()
  | L _, _ -> -1 | _, L _ -> 1
  | ST _, ST _ -> compare_contents ()
  | ST _, _ -> -1 | _, ST _ -> 1
  | O _, O _ -> compare_contents ()
  | O _, _ -> -1 | _, O _ -> 1
  | OU _, OU _ -> compare_contents ()
  | OU _, _ -> -1 | _, OU _ -> 1
  | T _, T _ -> compare_contents ()
  | T _, _ -> -1 | _, T _ -> 1
  | DNQ _, DNQ _ -> compare_contents ()
  | DNQ _, _ -> -1 | _, DNQ _ -> 1
  | Mail _, Mail _ -> compare_contents ()
  | Mail _, _ -> -1 | _, Mail _ -> 1
  | DC _, DC _ -> compare_contents ()
  | DC _, _ -> -1 | _, DC _ -> 1
  | Given_name _, Given_name _ -> compare_contents ()
  | Given_name _, _ -> -1 | _, Given_name _ -> 1
  | Surname _, Surname _ -> compare_contents ()
  | Surname _, _ -> -1 | _, Surname _ -> 1
  | Initials _, Initials _ -> compare_contents ()
  | Initials _, _ -> -1 | _, Initials _ -> 1
  | Pseudonym _, Pseudonym _ -> compare_contents ()
  | Pseudonym _, _ -> -1 | _, Pseudonym _ -> 1
  | Generation _, Generation _ -> compare_contents ()
  | Generation _, _ -> -1 | _, Generation _ -> 1
  | Street _, Street _ -> compare_contents ()
  | Street _, _ -> -1 | _, Street _ -> 1
  | Userid _, Userid _ -> compare_contents ()
  | Userid _, _ -> -1 | _, Userid _ -> 1
  | Other a, Other b ->
    match Asn.OID.compare (Other_attribute.oid a) (Other_attribute.oid b) with
    | 0 -> compare_contents ()
    | x when x < 0 -> -1
    | _ -> 1

module Relative_distinguished_name = Set.Make(struct
    type t = attribute
    let compare = compare_attribute Encoded_string.compare
  end)

let compare_attribute_for_matching a b =
  match a, b with
  (* Unknown attributes have no known string matching rule. *)
  | Other _, Other _ -> compare_attribute Encoded_string.compare a b
  | _ -> compare_attribute Encoded_string.compare_for_matching a b

(* TODO: each RDN should be a non-empty set. *)
type t = Relative_distinguished_name.t list

let equal a b =
  List.length a = List.length b &&
  List.for_all2 Relative_distinguished_name.equal a b

let matches a b =
  let attributes rdn =
    List.sort compare_attribute_for_matching (Relative_distinguished_name.elements rdn)
  in
  let rdn_matches a b =
    Relative_distinguished_name.cardinal a = Relative_distinguished_name.cardinal b &&
    List.for_all2 (fun a b -> compare_attribute_for_matching a b = 0)
      (attributes a) (attributes b)
  in
  List.length a = List.length b && List.for_all2 rdn_matches a b

let make_pp_rdn ?osf ?(spacing = `Tight) () =
  let ava_sep, ava_equal =
    match spacing with
    | `Tight -> Fmt.(any "+" ++ cut, any "=")
    | `Medium -> Fmt.(any " +" ++ sp, any "=")
    | `Loose -> Fmt.(any " +" ++ sp, any " = ")
  in
  let pp_ava = pp_attribute ?osf ~ava_equal () in
  Fmt.(using Relative_distinguished_name.elements @@ list ~sep:ava_sep pp_ava)

let make_pp ~format ?spacing () =
  match format, spacing with
  | `RFC4514, (None | Some `Tight) ->
    Fmt.(using List.rev @@ list ~sep:(any "," ++ cut) (make_pp_rdn ()))
  | `RFC4514, Some (`Medium | `Loose as spacing) ->
    Fmt.(using List.rev @@ list ~sep:comma (make_pp_rdn ~spacing ()))
  | `OpenSSL, (None | Some `Loose) ->
    Fmt.(list ~sep:comma (make_pp_rdn ~spacing:`Loose ()))
  | `OpenSSL, Some (`Tight | `Medium as spacing) ->
    Fmt.(list ~sep:(any "," ++ cut) (make_pp_rdn ~spacing ()))
  | `OSF, _ ->
    Fmt.(any "/" ++ list ~sep:(any "/") (make_pp_rdn ~osf:true ()))

let pp = Fmt.hbox (make_pp ~format:`OSF ())

let common_name t =
  List.fold_left (fun acc dn ->
      (* CN sorts before other attributes. *)
      match Relative_distinguished_name.min_elt_opt dn with
      | Some (CN value) -> Some value
      | _ -> acc)
    None t

module Asn = struct
  open Asn.S
  open Asn_grammars

  (* ASN `Name' fragmet appears all over. *)

  (* rfc5280 section 4.1.2.4 - name components we "must" handle. *)
  (* A list of abbreviations: http://pic.dhe.ibm.com/infocenter/wmqv7/v7r1/index.jsp?topic=%2Fcom.ibm.mq.doc%2Fsy10570_.htm *)
  (* Also rfc4519. *)

  let encoded_string =
    choice6
      utf8_string printable_string
      ia5_string universal_string teletex_string bmp_string

  let or_parse_error = function
    | Ok value -> value
    | Error (`Msg message) -> parse_error "%s" message

  let directory = function
    | `C1 x -> Encoded_string.of_string ~encoding:(`UTF8 : Encoded_string.directory_encoding) x
    | `C2 x -> Encoded_string.of_string ~encoding:(`Printable : Encoded_string.directory_encoding) x
    | `C3 _ -> parse_error "IA5String is not a DirectoryString"
    | `C4 x -> Encoded_string.of_string ~encoding:(`Universal : Encoded_string.directory_encoding) x
    | `C5 x -> Encoded_string.of_string ~encoding:(`Teletex : Encoded_string.directory_encoding) x
    | `C6 x -> Encoded_string.of_string ~encoding:(`BMP : Encoded_string.directory_encoding) x

  let printable = function
    | `C2 x -> Encoded_string.of_string ~encoding:`Printable x
    | _ -> parse_error "attribute requires PrintableString"

  let ia5 = function
    | `C3 x -> Encoded_string.of_string ~encoding:`IA5 x
    | _ -> parse_error "attribute requires IA5String"

  let name =
    let open Registry in
    let of_c = function
      | `C1 x -> Encoded_string.of_string ~encoding:(`UTF8 : Encoded_string.encoding) x
      | `C2 x -> Encoded_string.of_string ~encoding:(`Printable : Encoded_string.encoding) x
      | `C3 x -> Encoded_string.of_string ~encoding:(`IA5 : Encoded_string.encoding) x
      | `C4 x -> Encoded_string.of_string ~encoding:(`Universal : Encoded_string.encoding) x
      | `C5 x -> Encoded_string.of_string ~encoding:(`Teletex : Encoded_string.encoding) x
      | `C6 x -> Encoded_string.of_string ~encoding:(`BMP : Encoded_string.encoding) x
    and to_c x =
      let octets = Encoded_string.to_string x in
      match Encoded_string.encoding x with
      | `UTF8 -> `C1 octets
      | `Printable -> `C2 octets
      | `IA5 -> `C3 octets
      | `Universal -> `C4 octets
      | `Teletex -> `C5 octets
      | `BMP -> `C6 octets
    in

    let a_f = case_of_oid_f [
      (domain_component              , fun x -> DC (ia5 x)) ;
      (X520.common_name              , fun x -> CN (Common_name.of_encoded (directory x))) ;
      (X520.serial_number            , fun x -> Serialnumber (Serial_number.of_encoded (printable x))) ;
      (X520.country_name             , fun x -> C (Country_name.of_encoded (printable x))) ;
      (X520.locality_name            , fun x -> L (Locality_name.of_encoded (directory x))) ;
      (X520.state_or_province_name   , fun x -> ST (State_or_province_name.of_encoded (directory x))) ;
      (X520.organization_name        , fun x -> O (Organization_name.of_encoded (directory x))) ;
      (X520.organizational_unit_name , fun x -> OU (Organizational_unit_name.of_encoded (directory x))) ;
      (X520.title                    , fun x -> T (Title.of_encoded (directory x))) ;
      (X520.dn_qualifier             , fun x -> DNQ (printable x)) ;
      (PKCS9.email                   , fun x -> Mail (Email_address.of_encoded (ia5 x))) ;
      (X520.given_name               , fun x -> Given_name (Personal_name.of_encoded (directory x))) ;
      (X520.surname                  , fun x -> Surname (Personal_name.of_encoded (directory x))) ;
      (X520.initials                 , fun x -> Initials (Personal_name.of_encoded (directory x))) ;
      (X520.pseudonym                , fun x -> Pseudonym (Pseudonym.of_encoded (directory x))) ;
      (X520.generation_qualifier     , fun x -> Generation (Personal_name.of_encoded (directory x))) ;
      (X520.street_address           , fun x -> Street (Street_address.of_encoded (directory x))) ;
      (userid                        , fun x -> Userid (User_id.of_encoded (directory x)))]
      ~default:(fun oid x -> Other (or_parse_error (Other_attribute.create oid (of_c x))))

    and a_g attr =
      let value = to_c (attribute_value attr) in
      match attr with
      | DC _ -> (domain_component, value)
      | CN _ -> (X520.common_name, value)
      | Serialnumber _ -> (X520.serial_number, value)
      | C _ -> (X520.country_name, value)
      | L _ -> (X520.locality_name, value)
      | ST _ -> (X520.state_or_province_name, value)
      | O _ -> (X520.organization_name, value)
      | OU _ -> (X520.organizational_unit_name, value)
      | T _ -> (X520.title, value)
      | DNQ _ -> (X520.dn_qualifier, value)
      | Mail _ -> (PKCS9.email, value)
      | Given_name _ -> (X520.given_name, value)
      | Surname _ -> (X520.surname, value)
      | Initials _ -> (X520.initials, value)
      | Pseudonym _ -> (X520.pseudonym, value)
      | Generation _ -> (X520.generation_qualifier, value)
      | Street _ -> (X520.street_address, value)
      | Userid _ -> (userid, value)
      | Other other -> (Other_attribute.oid other, value)
    in

    let attribute_tv =
      map a_f a_g @@
      sequence2
        (required ~label:"attr type"  oid)
        (* This is ANY according to rfc5280. *)
        (required ~label:"attr value" encoded_string)
    in
    let rd_name =
      let f exts =
        List.fold_left
          (fun set attr -> Relative_distinguished_name.add attr set)
          Relative_distinguished_name.empty exts
      and g map = Relative_distinguished_name.elements map
      in
      map f g @@ set_of attribute_tv
    in
    sequence_of rd_name (* A vacuous choice, in the standard. *)

  let (name_of_octets, name_to_octets) =
    projections_of Asn.der name
end

let decode_der cs = Asn_grammars.err_to_msg (Asn.name_of_octets cs)

let encode_der = Asn.name_to_octets
