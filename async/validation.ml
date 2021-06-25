open! Core
open! Async
open! Import
include X509.Validation

let ca_error_to_string = Fmt.to_to_string pp_ca_error
let sexp_of_ca_error e = sexp_of_string (ca_error_to_string e)
let signature_error_to_string = Fmt.to_to_string pp_signature_error
let sexp_of_signature_error e = sexp_of_string (signature_error_to_string e)
let validation_error_to_string = Fmt.to_to_string pp_validation_error
let sexp_of_validation_error e = sexp_of_string (validation_error_to_string e)
