open Rresult

module Cs = struct
  open Cstruct

  let begins_with cs target =
    let l1 = len cs and l2 = len target in
    l1 >= l2 && equal (sub cs 0 l2) target

  let ends_with cs target =
    let l1 = len cs and l2 = len target in
    l1 >= l2 && equal (sub cs (l1 - l2) l2) target

  let null cs = len cs = 0

  let open_begin = of_string "-----BEGIN "
  and open_end   = of_string "-----END "
  and close      = of_string "-----"

  let tok_of_line cs =
    if null cs then
      `Empty
    else if get_char cs 0 = '#' then
      `Empty
    else if begins_with cs open_begin && ends_with cs close then
      `Begin (to_string @@ sub cs 11 (len cs - 16))
    else if begins_with cs open_end && ends_with cs close then
      `End (to_string @@ sub cs 9 (len cs - 14))
    else
      `Data cs

  let chop cs off len =
    let (a, b) = split cs off in (a, shift b len)

  let rec lines cs =
    let rec eol i =
      match get_char cs i with
      | '\r' when get_char cs (i + 1) = '\n' -> chop cs i 2
      | '\n' -> chop cs i 1
      | _    -> eol (i + 1) in
    match eol 0 with
    | exception Invalid_argument _ -> [ tok_of_line cs ]
    | a, b -> tok_of_line a :: lines b

  let combine ilines =
    let rec accumulate t acc = function
      | `Empty :: tail -> accumulate t acc tail
      | `Data cs :: tail -> accumulate t (cs :: acc) tail
      | `End t' :: tail ->
        if String.equal t t' then
          Ok (concat (List.rev acc), tail)
        else
          Error (`Parse ("invalid end, expected " ^ t ^ ", found " ^ t'))
      | _ :: _ -> Error (`Parse "invalid line, expected data or end")
      | [] -> Error (`Parse "end of input")
    in

    let rec block acc = function
      | `Begin t :: tail ->
        accumulate t [] tail >>= fun (body, tail) ->
        R.of_option ~none:(fun () -> Error (`Parse "base64 decoding failed"))
          (Nocrypto.Base64.decode body) >>= fun data ->
        block ((t, data) :: acc) tail
      | _::xs -> block acc xs
      | []    -> Ok (List.rev acc)
    in
    block [] ilines

  let parse data= combine (lines data)

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
    concat (first @ lines @ last)
end

let parse, unparse = Cs.(parse, unparse)

let exactly_one ~what = function
  | []  -> Error (`Parse ("No " ^ what))
  | [x] -> Ok x
  | _   -> Error (`Parse ("Multiple " ^ what ^ "s"))

let foldM f data =
  let wrap acc data =
    acc >>= fun datas' ->
    f data >>| fun data ->
    data :: datas'
  in
  List.fold_left wrap (Ok []) data >>| List.rev

module Certificate = struct
  let of_pem_cstruct cs =
    Cs.parse cs >>= fun data ->
    let certs = List.filter (fun (t, _) -> String.equal "CERTIFICATE" t) data in
    foldM (fun (_, cs) -> X509_certificate.parse_certificate cs) certs

  let of_pem_cstruct1 cs =
    of_pem_cstruct cs >>= exactly_one ~what:"certificate"

  let to_pem_cstruct1 v =
    Cs.unparse ~tag:"CERTIFICATE" (X509_certificate.cs_of_cert v)

  let to_pem_cstruct cs =
    Cstruct.concat (List.map to_pem_cstruct1 cs)
end

module Certificate_signing_request = struct
  let of_pem_cstruct cs =
    Cs.parse cs >>= fun data ->
    let crs =
      List.filter (fun (t, _) -> String.equal "CERTIFICATE REQUEST" t) data
    in
    foldM (fun (_, cs) -> X509_ca.parse_signing_request cs) crs

  let of_pem_cstruct1 cs =
    of_pem_cstruct cs >>= exactly_one ~what:"certificate request"

  let to_pem_cstruct1 v =
    Cs.unparse ~tag:"CERTIFICATE REQUEST"
      (Asn_grammars.CertificateRequest.certificate_request_to_cs v)

  let to_pem_cstruct cs =
    Cstruct.concat (List.map to_pem_cstruct1 cs)
end

module Public_key = struct
  let of_pem_cstruct cs =
    Cs.parse cs >>= fun data ->
    let pks = List.filter (fun (t, _) -> String.equal "PUBLIC KEY" t) data in
    foldM (fun (_, cs) -> Asn_grammars.PK.pub_info_of_cstruct cs) pks

  let of_pem_cstruct1 cs =
    of_pem_cstruct cs >>= exactly_one ~what:"public key"

  let to_pem_cstruct1 v =
    Cs.unparse ~tag:"PUBLIC KEY" (Asn_grammars.PK.pub_info_to_cstruct v)

  let to_pem_cstruct cs =
    Cstruct.concat (List.map to_pem_cstruct1 cs)
end

module Private_key = struct
  let of_pem_cstruct cs =
    Cs.parse cs >>= fun data ->
    let rsa_p (t, _) = String.equal "RSA PRIVATE KEY" t
    and pk_p (t, _) = String.equal "PRIVATE KEY" t
    in
    let rsas, _ = List.partition rsa_p data
    and privs, _ = List.partition pk_p data
    in
    let open Asn_grammars.PK in
    foldM (fun (_, cs) -> rsa_private_of_cstruct cs) rsas >>= fun k ->
    foldM (fun (_, cs) -> private_of_cstruct cs) privs >>| fun k' ->
    List.map (fun k -> `RSA k) (k @ k')

  let of_pem_cstruct1 cs = of_pem_cstruct cs >>= exactly_one ~what:"RSA key"

  let to_pem_cstruct1 = function
    | `RSA v -> Cs.unparse ~tag:"RSA PRIVATE KEY"
                  (Asn_grammars.PK.rsa_private_to_cstruct v)

  let to_pem_cstruct cs =
    Cstruct.concat (List.map to_pem_cstruct1 cs)
end
