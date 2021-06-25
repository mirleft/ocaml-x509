open! Core
open! Async
open! Import

include module type of struct
  include X509.CRL
end

val decode_der : contents:string -> t Or_error.t
val verification_error_to_string : verification_error -> string
val sexp_of_verification_error : verification_error -> Sexp.t

val revoke
  :  ?digest:Mirage_crypto.Hash.hash
  -> issuer:X509.Distinguished_name.t
  -> this_update:Ptime.t
  -> ?next_update:Ptime.t
  -> ?extensions:X509.Extension.t
  -> revoked_cert list
  -> X509.Private_key.t
  -> t Or_error.t

val revoke_certificate
  :  revoked_cert
  -> this_update:Ptime.t
  -> ?next_update:Ptime.t
  -> t
  -> X509.Private_key.t
  -> t Or_error.t

val revoke_certificates
  :  revoked_cert list
  -> this_update:Ptime.t
  -> ?next_update:Ptime.t
  -> t
  -> X509.Private_key.t
  -> t Or_error.t

val of_pem_dir : directory:Filename.t -> t list Deferred.Or_error.t
