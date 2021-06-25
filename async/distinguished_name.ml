open! Core
open! Async
open! Import
include X509.Distinguished_name

let to_string = Fmt.to_to_string pp
let decode_der = Or_error.lift_result_msg_of_cstruct decode_der
