type _ k =
  | CN : string k
  | Serialnumber : string k
  | C : string k
  | L : string k
  | SP : string k
  | O : string k
  | OU : string k
  | T : string k
  | DNQ : string k
  | Mail : string k
  | DC : string k
  | Given_name : string k
  | Surname : string k
  | Initials : string k
  | Pseudonym : string k
  | Generation : string k
  | Other : Asn.oid -> string k

module K = struct
  type 'a t = 'a k

  let compare : type a b. a t -> b t -> (a, b) Gmap.Order.t = fun t t' ->
    let open Gmap.Order in
    match t, t' with
    | CN, CN -> Eq | CN, _ -> Lt | _, CN -> Gt
    | Serialnumber, Serialnumber -> Eq | Serialnumber, _ -> Lt | _, Serialnumber -> Gt
    | C, C -> Eq | C, _ -> Lt | _, C -> Gt
    | L, L -> Eq | L, _ -> Lt | _, L -> Gt
    | SP, SP -> Eq | SP, _ -> Lt | _, SP -> Gt
    | O, O -> Eq | O, _ -> Lt | _, O -> Gt
    | OU, OU -> Eq | OU, _ -> Lt | _, OU -> Gt
    | T, T -> Eq | T, _ -> Lt | _, T -> Gt
    | DNQ, DNQ -> Eq | DNQ, _ -> Lt | _, DNQ -> Gt
    | Mail, Mail -> Eq | Mail, _ -> Lt | _, Mail -> Gt
    | DC, DC -> Eq | DC, _ -> Lt | _, DC -> Gt
    | Given_name, Given_name -> Eq | Given_name, _ -> Lt | _, Given_name -> Gt
    | Surname, Surname -> Eq | Surname, _ -> Lt | _, Surname -> Gt
    | Initials, Initials -> Eq | Initials, _ -> Lt | _, Initials -> Gt
    | Pseudonym, Pseudonym -> Eq | Pseudonym, _ -> Lt | _, Pseudonym -> Gt
    | Generation, Generation -> Eq | Generation, _ -> Lt | _, Generation -> Gt
    | Other a, Other b ->
      match Asn.OID.compare a b with
      | 0 -> Eq
      | x when x < 0 -> Lt
      | _ -> Gt
end

include Gmap.Make(K)

let pp_component : type a. a k -> Format.formatter -> a -> unit = fun k ppf v ->
  match k, v with
  | CN, s -> Fmt.pf ppf "CN=%s" s
  | Serialnumber, s -> Fmt.pf ppf "Serialnumber=%s" s
  | C, s -> Fmt.pf ppf "C=%s" s
  | L, s -> Fmt.pf ppf "L=%s" s
  | SP, s -> Fmt.pf ppf "SP=%s" s
  | O, s -> Fmt.pf ppf "O=%s" s
  | OU, s -> Fmt.pf ppf "OU=%s" s
  | T, s -> Fmt.pf ppf "T=%s" s
  | DNQ, s -> Fmt.pf ppf "DNQ=%s" s
  | Mail, s -> Fmt.pf ppf "Mail=%s" s
  | DC, s -> Fmt.pf ppf "DC=%s" s
  | Given_name, s -> Fmt.pf ppf "Given_name=%s" s
  | Surname, s -> Fmt.pf ppf "Surname=%s" s
  | Initials, s -> Fmt.pf ppf "Initials=%s" s
  | Pseudonym, s -> Fmt.pf ppf "Pseudonym=%s" s
  | Generation, s -> Fmt.pf ppf "Generation=%s" s
  | Other oid, s -> Fmt.pf ppf "%a=%s" Asn.OID.pp oid s

let equal a b = equal { f = fun _ a b -> compare a b = 0 } a b

let pp ppf dn =
  let pp_b ppf (B (k, v)) = pp_component k ppf v in
  Fmt.(list ~sep:(unit "/") pp_b) ppf (bindings dn)

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
      (domain_component              , fun x -> B (DC, x)) ;
      (X520.common_name              , fun x -> B (CN, x)) ;
      (X520.serial_number            , fun x -> B (Serialnumber, x)) ;
      (X520.country_name             , fun x -> B (C, x)) ;
      (X520.locality_name            , fun x -> B (L, x)) ;
      (X520.state_or_province_name   , fun x -> B (SP, x)) ;
      (X520.organization_name        , fun x -> B (O, x)) ;
      (X520.organizational_unit_name , fun x -> B (OU, x)) ;
      (X520.title                    , fun x -> B (T, x)) ;
      (X520.dn_qualifier             , fun x -> B (DNQ, x)) ;
      (PKCS9.email                   , fun x -> B (Mail, x)) ;
      (X520.given_name               , fun x -> B (Given_name, x)) ;
      (X520.surname                  , fun x -> B (Surname, x)) ;
      (X520.initials                 , fun x -> B (Initials, x)) ;
      (X520.pseudonym                , fun x -> B (Pseudonym, x)) ;
      (X520.generation_qualifier     , fun x -> B (Generation, x)) ]
      ~default:(fun oid x -> B (Other oid, x))

    and a_g (B (k, v)) : Asn.oid * string = match k, v with
      | DC, x -> (domain_component, x )
      | CN, x -> (X520.common_name, x )
      | Serialnumber, x -> (X520.serial_number, x )
      | C, x   -> (X520.country_name, x )
      | L, x   -> (X520.locality_name, x )
      | SP, x   -> (X520.state_or_province_name, x )
      | O, x   -> (X520.organization_name, x )
      | OU, x   -> (X520.organizational_unit_name, x )
      | T, x   -> (X520.title, x )
      | DNQ, x   -> (X520.dn_qualifier, x )
      | Mail, x   -> (PKCS9.email, x )
      | Given_name, x   -> (X520.given_name, x )
      | Surname, x   -> (X520.surname, x )
      | Initials, x   -> (X520.initials, x )
      | Pseudonym, x   -> (X520.pseudonym, x )
      | Generation, x   -> (X520.generation_qualifier, x )
      | Other oid, x -> (oid, x )
    in

    let attribute_tv =
      map a_f a_g @@
      sequence2
        (required ~label:"attr type"  oid)
        (* This is ANY according to rfc5280. *)
        (required ~label:"attr value" directory_name)
    in
    let rd_name =
      let f exts =
        List.fold_left (fun map (B (k, v)) ->
            match add_unless_bound k v map with
            | None -> parse_error "%a already bound" (pp_component k) v
            | Some b -> b)
          empty exts
      and g map = bindings map
      in
      map f g @@ set_of attribute_tv
    in
    let rdn_sequence =
      let f rdns =
        (* for each component, the last one present in any rdn wins *)
        List.fold_left (fun m a -> union { f = fun _ _ y -> Some y } m a)
          empty rdns
      and g map = [ map ]
      in
      map f g @@ sequence_of rd_name
    in
    rdn_sequence (* A vacuous choice, in the standard. *)

  let (name_of_cstruct, name_to_cstruct) =
    projections_of Asn.der name
end

let decode_der cs = Asn_grammars.err_to_msg (Asn.name_of_cstruct cs)

let encode_der = Asn.name_to_cstruct
