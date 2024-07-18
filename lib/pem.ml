let ( let* ) = Result.bind

module Cs = struct
  open String

  let split str off =
    String.sub str 0 off,
    String.sub str off (String.length str - off)

  let shift str off = snd (split str off)

  let begins_with cs target =
    let l1 = length cs and l2 = length target in
    l1 >= l2 && equal (sub cs 0 l2) target

  let ends_with cs target =
    let l1 = length cs and l2 = length target in
    l1 >= l2 && equal (sub cs (l1 - l2) l2) target

  let null cs = length cs = 0

  let open_begin = "-----BEGIN "
  and open_end   = "-----END "
  and close      = "-----"

  let tok_of_line cs =
    if null cs then
      `Empty
    else if get cs 0 = '#' then
      `Empty
    else if begins_with cs open_begin && ends_with cs close then
      `Begin (sub cs 11 (length cs - 16))
    else if begins_with cs open_end && ends_with cs close then
      `End (sub cs 9 (length cs - 14))
    else
      `Data cs

  let chop cs off len =
    let (a, b) = split cs off in (a, shift b len)

  let rec lines cs =
    let rec eol i =
      match get cs i with
      | '\r' when get cs (i + 1) = '\n' -> chop cs i 2
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
          let data = match Base64.decode (concat "" (List.rev acc)) with
            | Ok data -> Ok (t, data)
            | Error e -> Error e
          in
          data, tail
        else
          Error (`Msg ("invalid end, expected " ^ t ^ ", found " ^ t')), tail
      | _ :: tail -> Error (`Msg "invalid line, expected data or end"), tail
      | [] -> Error (`Msg "end of input"), []
    in

    let rec block acc = function
      | `Begin t :: tail ->
        let body, tail = accumulate t [] tail in
        block (body :: acc) tail
      | _::xs -> block acc xs
      | [] -> List.rev acc
    in
    block [] ilines

  let parse_with_errors data = combine (lines data)

  let unparse ~tag value =
    let rec split_at_64 acc = function
      | x when length x <= 64 -> List.rev (x :: acc)
      | x -> let here, rest = split x 64 in
        split_at_64 (here :: acc) rest
    in
    let raw = Base64.encode_string value in
    let pieces = split_at_64 [] raw in
    let nl = "\n" in
    let lines = List.flatten (List.map (fun x -> [ x ; nl ]) pieces)
    in

    let first = [ open_begin ; tag ; close ; nl ]
    and last = [ open_end ; tag ; close ; nl ]
    in
    concat "" (first @ lines @ last)
end

let parse_with_errors, unparse = Cs.(parse_with_errors, unparse)

let parse data =
  let entries, errors =
    List.partition_map
      (function Ok v -> Either.Left v | Error e -> Either.Right e)
      (parse_with_errors data)
  in
  match errors with
  | [] -> Ok entries
  | first_error :: _ -> Error first_error

let exactly_one ~what = function
  | []  -> Error (`Msg ("No " ^ what))
  | [x] -> Ok x
  | _   -> Error (`Msg ("Multiple " ^ what ^ "s"))

let foldM f data =
  let wrap acc data =
    let* datas' = acc in
    let* data = f data in
    Ok (data :: datas')
  in
  let* res = List.fold_left wrap (Ok []) data in
  Ok (List.rev res)
