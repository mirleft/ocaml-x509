open! Core
open! Async
open! Import
include X509.CRL

let decode_der = Or_error.lift_result_msg_of_cstruct decode_der
let verification_error_to_string = Fmt.to_to_string pp_verification_error
let sexp_of_verification_error e = sexp_of_string (verification_error_to_string e)

let revoke ?digest ~issuer ~this_update ?next_update ?extensions revoked_certs key =
  revoke ?digest ~issuer ~this_update ?next_update ?extensions revoked_certs key
  |> Or_error.of_result_msg
;;

let revoke_certificate revoked ~this_update ?next_update crl key =
  revoke_certificate revoked ~this_update ?next_update crl key |> Or_error.of_result_msg
;;

let revoke_certificates revoked ~this_update ?next_update crl key =
  revoke_certificates revoked ~this_update ?next_update crl key |> Or_error.of_result_msg
;;

let of_pem_dir ~directory =
  load_all_in_directory ~directory ~f:(fun ~contents ->
    decode_der ~contents |> Deferred.return)
;;
