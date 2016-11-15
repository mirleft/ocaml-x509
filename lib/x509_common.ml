include Result

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

module Ptime = struct
  include Ptime
  open Sexplib
  let t_of_sexp sx = match sx with
    | Sexp.List _  -> Conv.of_sexp_error "Ptime.t_of_sexp: expected Atom" sx
    | Sexp.Atom ts ->
        match of_rfc3339 ts |> rfc3339_error_to_msg with
        | Ok (t, _, _)   -> t
        | Error (`Msg e) -> Conv.of_sexp_error ("Ptime.t_of_sexp: " ^ e) sx
  let sexp_of_t t = Sexp.Atom (to_rfc3339 ~tz_offset_s:0 t)
end
