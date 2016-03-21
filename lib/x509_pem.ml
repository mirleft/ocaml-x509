open Cstruct

let o f g x = f (g x)

module Cs = struct

  open Cstruct
  include Nocrypto.Uncommon.Cs

  let begins_with cs target =
    let l1 = len cs and l2 = len target in
    l1 >= l2 && equal (sub cs 0 l2) target

  let ends_with cs target =
    let l1 = len cs and l2 = len target in
    l1 >= l2 && equal (sub cs (l1 - l2) l2) target
end

let null cs = Cstruct.len cs = 0

let open_begin = of_string "-----BEGIN "
and open_end   = of_string "-----END "
and close      = of_string "-----"

let catch f a =
  try Some (f a) with Invalid_argument _ -> None

let tok_of_line cs =
  try
    if ( null cs ) then
      `Empty else
    if ( get_char cs 0 = '#' ) then
      `Empty else
    if ( Cs.begins_with cs open_begin &&
         Cs.ends_with cs close ) then
      `Begin (to_string @@ sub cs 11 (len cs - 16)) else
    if ( Cs.begins_with cs open_end &&
         Cs.ends_with cs close ) then
      `End (to_string @@ sub cs 9 (len cs - 14)) else
      `Data cs
  with Invalid_argument _ -> `Data cs

let chop cs off len =
  let (a, b) = split cs off in (a, shift b len)

let rec lines cs =
  let rec eol i =
    match get_char cs i with
    | '\r' when get_char cs (i + 1) = '\n' -> chop cs i 2
    | '\n' -> chop cs i 1
    | _    -> eol (i + 1) in
  match catch eol 0 with
  | Some (a, b) -> tok_of_line a :: lines b
  | None        -> [ tok_of_line cs ]

let combine ilines =

  let rec accumulate t acc = function
    | `Empty :: tail -> accumulate t acc tail
    | `Data cs :: tail -> accumulate t (cs :: acc) tail
    | `End t' :: tail when t = t' -> (Cstruct.concat (List.rev acc), tail)
    | _ :: tail -> (Cs.empty, tail)
    | [] -> (Cs.empty, [])

  and block = function
    | `Begin t :: tail ->
      let body, tail = accumulate t [] tail in
      ( match Nocrypto.Base64.decode body with
        | None      -> invalid_arg "PEM: malformed Base64 data"
        | Some data -> (t, data) :: block tail )
    | _::xs -> block xs
    | []    -> []
  in
  block ilines

let parse = o combine lines

let exactly_one ~what = function
  | []  -> invalid_arg ("No " ^ what)
  | [x] -> x
  | _   -> invalid_arg ("Multiple " ^ what)

let unparse ~tag value =
  let rec split_at_64 acc = function
    | x when len x <= 64 -> List.rev (x :: acc)
    | x -> let here, rest = split x 64 in
           split_at_64 (here :: acc) rest
  in
  let raw = Nocrypto.Base64.encode value in
  let pieces = split_at_64 [] raw in
  let nl = of_string "\n" in
  let lines = List.flatten (List.map (fun x -> [ x ; nl ]) pieces)
  in

  let tag = of_string tag in
  let first = [ open_begin ; tag ; close ; nl ]
  and last = [ open_end ; tag ; close ; nl ]
  in
  Cstruct.concat (first @ lines @ last)

module Certificate = struct

  let of_pem_cstruct cs =
    List.fold_left (fun certs -> function
        | ("CERTIFICATE", cs) ->
          ( match X509_certificate.parse_certificate cs with
            | Some cert -> certs @ [cert]
            | None      -> invalid_arg "X509: failed to parse certificate" )
        | _ -> certs)
      []
      (parse cs)

  let of_pem_cstruct1 =
    o (exactly_one ~what:"certificates") of_pem_cstruct

  let to_pem_cstruct1 v =
    unparse ~tag:"CERTIFICATE" (X509_certificate.cs_of_cert v)

  let to_pem_cstruct cs =
    Cstruct.concat (List.map to_pem_cstruct1 cs)
end

module Certificate_signing_request = struct

  type t = X509_ca.signing_request

  let of_pem_cstruct cs =
    List.fold_left (fun csrs -> function
        | ("CERTIFICATE REQUEST", cs) ->
          ( match X509_ca.parse_signing_request cs with
            | Some csr -> csrs @ [csr]
            | None     -> invalid_arg "X509: failed to parse certificate signing request" )
        | _ -> csrs)
      []
      (parse cs)

  let of_pem_cstruct1 =
    o (exactly_one ~what:"certificate request") of_pem_cstruct

  let to_pem_cstruct1 v =
    unparse ~tag:"CERTIFICATE REQUEST" (X509_ca.cs_of_signing_request v)

  let to_pem_cstruct cs =
    Cstruct.concat (List.map to_pem_cstruct1 cs)
end

module Public_key = struct
  let of_pem_cstruct cs =
    List.fold_left (fun keys -> function
        | ("PUBLIC KEY", cs) ->
          ( match Asn_grammars.PK.pub_info_of_cstruct cs with
            | Some key -> keys @ [key]
            | None     -> invalid_arg "X509: failed to parse public key" )
        | _ -> keys)
      []
      (parse cs)

  let of_pem_cstruct1 =
    o (exactly_one ~what:"public keys") of_pem_cstruct

  let to_pem_cstruct1 v =
    unparse ~tag:"PUBLIC KEY" (Asn_grammars.PK.pub_info_to_cstruct v)

  let to_pem_cstruct cs =
    Cstruct.concat (List.map to_pem_cstruct1 cs)
end

module Private_key = struct
  let of_pem_cstruct cs =
    List.fold_left (fun pks -> function
        | ("RSA PRIVATE KEY", cs) ->
          ( match Asn_grammars.PK.rsa_private_of_cstruct cs with
            | Some pk -> (`RSA pk) :: pks
            | None    -> invalid_arg "X509: failed to parse rsa private key" )
        | ("PRIVATE KEY", cs) ->
          ( match Asn_grammars.PK.private_of_cstruct cs with
            | Some pk -> (`RSA pk) :: pks
            | None    -> invalid_arg "X509: failed to parse private key" )
        | _ -> pks)
      []
      (parse cs)

  let of_pem_cstruct1 =
    o (exactly_one ~what:"RSA keys") of_pem_cstruct

  let to_pem_cstruct1 = function
    | `RSA v -> unparse ~tag:"RSA PRIVATE KEY" (Asn_grammars.PK.rsa_private_to_cstruct v)

  let to_pem_cstruct cs =
    Cstruct.concat (List.map to_pem_cstruct1 cs)
end
