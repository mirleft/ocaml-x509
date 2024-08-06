let ( let* ) = Result.bind

module Cs = struct
  open String

  let null cs = length cs = 0

  let open_begin = "-----BEGIN "
  and open_end   = "-----END "
  and close      = "-----"

  let tok_of_line cs =
    if null cs then
      `Empty
    else if get cs 0 = '#' then
      `Empty
    else if starts_with ~prefix:open_begin cs && ends_with ~suffix:close cs then
      `Begin (sub cs 11 (length cs - 16))
    else if starts_with ~prefix:open_end cs && ends_with ~suffix:close cs then
      `End (sub cs 9 (length cs - 14))
    else
      `Data cs

  let lines data =
    List.map tok_of_line
      (List.map
         (fun line ->
            let ll = length line in
            if ll > 0 && get line (ll - 1) = '\r' then sub line 0 (ll - 1) else line)
         (String.split_on_char '\n' data))

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
      | _ :: xs -> block acc xs
      | [] -> List.rev acc
    in
    block [] ilines

  let parse_with_errors data = combine (lines data)

  let unparse ~tag value =
    let split_at_64 data =
      let dlen = length data in
      let rec go acc off =
        if dlen - off <= 64 then
          List.rev (sub data off (dlen - off) :: acc)
        else
          let chunk = sub data off 64 in
          go (chunk :: acc) (off + 64)
      in
      go [] 0
    in
    let raw = Base64.encode_string value in
    let pieces = split_at_64 raw in
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
