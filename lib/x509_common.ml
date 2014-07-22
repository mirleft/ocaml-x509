
module String_ext = struct

  let rec split delimiter name =
    let rec doit len off acc =
      let open String in
      let idx = try index_from name off delimiter with _ -> len in
      let fst = sub name off (idx - off) in
      let idx' = idx + 1 in
      if idx' <= len then
        doit len idx' (fst :: acc)
      else
        fst :: acc
    in
    List.rev (doit (String.length name) 0 [])

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

