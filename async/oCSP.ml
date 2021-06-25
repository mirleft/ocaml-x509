open! Core
open! Async
open! Import
include X509.OCSP

module Request = struct
  include Request

  let create ?certs ?digest ?requestor_name ?key cert_ids =
    create ?certs ?digest ?requestor_name ?key cert_ids |> Or_error.of_result_msg
  ;;

  let decode_der = Or_error.lift_asn_error_of_cstruct decode_der
end

module Response = struct
  include Response

  let create_success
        ?digest
        ?certs
        ?response_extensions
        private_key
        responderID
        producedAt
        responses
    =
    create_success
      ?digest
      ?certs
      ?response_extensions
      private_key
      responderID
      producedAt
      responses
    |> Or_error.of_result_msg
  ;;

  let responses t = responses t |> Or_error.of_result_msg
  let decode_der = Or_error.lift_asn_error_of_cstruct decode_der
end
