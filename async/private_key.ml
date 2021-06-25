open! Core
open! Async
open! Import
include X509.Private_key

let sign hash ?scheme key data =
  sign hash ?scheme key data
  |> Or_error.of_result_msg
  |> Or_error.map ~f:Cstruct.to_string
;;

let decode_der = Or_error.lift_result_msg_of_cstruct decode_der
let decode_pem = Or_error.lift_result_msg_of_cstruct decode_pem

let of_pem_file file =
  let%map contents = Reader.file_contents file in
  decode_pem ~contents
;;
