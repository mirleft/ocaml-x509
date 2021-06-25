open! Core
open! Async
open! Import
include X509.Signing_request

let decode_der ?allowed_hashes der =
  Cstruct.of_string der |> decode_der ?allowed_hashes |> Or_error.of_result_msg
;;

let decode_pem pem = Cstruct.of_string pem |> decode_pem |> Or_error.of_result_msg

let create subject ?digest ?extensions key =
  create subject ?digest ?extensions key |> Or_error.of_result_msg
;;

let sign ?allowed_hashes ?digest ?serial ?extensions t key issuer ~valid_from ~valid_until
  =
  sign ?allowed_hashes ?digest ?serial ?extensions t key issuer ~valid_from ~valid_until
  |> Or_error.of_result ~to_string:Validation.signature_error_to_string
;;
