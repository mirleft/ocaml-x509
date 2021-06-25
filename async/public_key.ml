open! Core
open! Async
open! Import
include X509.Public_key

let verify hash ?scheme ~signature key data =
  let signature = Cstruct.of_string signature in
  let data =
    match data with
    | `Digest data -> `Digest (Cstruct.of_string data)
    | `Message data -> `Message (Cstruct.of_string data)
  in
  verify hash ?scheme ~signature key data |> Or_error.of_result_msg
;;

let decode_der = Or_error.lift_result_msg_of_cstruct decode_der
let decode_pem = Or_error.lift_result_msg_of_cstruct decode_pem
