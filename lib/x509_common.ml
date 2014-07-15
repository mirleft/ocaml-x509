
module String_ext = struct

  let rec split delimiter name =
    let open String in
    let len = length name in
    let idx = try index name delimiter with _ -> len in
    let fst = sub name 0 idx in
    let idx' = idx + 1 in
    if idx' <= len then
      let rt = sub name idx' (len - idx') in
      fst :: split delimiter rt
    else
      [fst]

end

module List_ext = struct

  let rec filter_map ~f = function
    | []    -> []
    | x::xs ->
        match f x with
        | None    ->       filter_map ~f xs
        | Some x' -> x' :: filter_map ~f xs

  let rec map_find ~f = function
    | []    -> None
    | x::xs ->
        match f x with
        | None         -> map_find ~f xs
        | Some _ as x' -> x'

end

