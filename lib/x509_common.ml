
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

module Hashtbl(T : Hashtbl.HashedType) = struct
  include Hashtbl.Make (T)
  let of_assoc xs =
    let ht = create 16 in List.iter (fun (a, b) -> add ht a b) xs; ht
end
