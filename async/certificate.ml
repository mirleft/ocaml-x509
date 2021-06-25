open! Core
open! Async
open! Import
include X509.Certificate
open Deferred.Or_error.Let_syntax

let decode_pem_multiple = Or_error.lift_result_msg_of_cstruct decode_pem_multiple
let decode_pem = Or_error.lift_result_msg_of_cstruct decode_pem
let decode_der = Or_error.lift_result_msg_of_cstruct decode_der

let of_pem_file ca_file =
  let%bind contents = file_contents ca_file in
  decode_pem_multiple ~contents |> Deferred.return
;;

let of_pem_directory ~directory =
  load_all_in_directory ~directory ~f:(fun ~contents ->
    decode_pem_multiple ~contents |> Deferred.return)
  >>| List.concat
;;
