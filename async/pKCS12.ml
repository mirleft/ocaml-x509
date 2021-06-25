open! Core
open! Async
open! Import
include X509.PKCS12

let decode_der = Or_error.lift_result_msg_of_cstruct decode_der
let verify password t = verify password t |> Or_error.of_result_msg
