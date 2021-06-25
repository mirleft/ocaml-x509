open! Core
open! Async
open Deferred.Or_error.Let_syntax

module Or_error = struct
  include Or_error

  let of_result ~to_string = Result.map_error ~f:(Fn.compose Error.of_string to_string)
  let of_result_msg x = of_result x ~to_string:(fun (`Msg msg) -> msg)

  let lift_result_msg_of_cstruct f ~contents =
    f (Cstruct.of_string contents) |> of_result_msg
  ;;

  let lift_asn_error_of_cstruct f ~contents =
    f (Cstruct.of_string contents) |> of_result ~to_string:(fun (`Parse msg) -> msg)
  ;;
end

let file_contents file =
  Deferred.Or_error.try_with ~name:(sprintf "read %s" file) (fun () ->
    Reader.file_contents file)
;;

let load_all_in_directory ~directory ~f =
  let options = Async_find.Options.ignore_errors in
  let%bind files = Async_find.find_all ~options directory |> Deferred.ok in
  Deferred.Or_error.List.map files ~f:(fun (file, (_ : Unix.Stats.t)) ->
    let%bind contents = file_contents file in
    f ~contents)
;;
