open! Core
open! Async
open! Import

include module type of struct
  include X509.Validation
end

val ca_error_to_string : ca_error -> string
val sexp_of_ca_error : ca_error -> Sexp.t
val signature_error_to_string : signature_error -> string
val sexp_of_signature_error : signature_error -> Sexp.t
val validation_error_to_string : validation_error -> string
val sexp_of_validation_error : validation_error -> Sexp.t
