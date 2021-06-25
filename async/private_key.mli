open! Core
open! Async
open! Import

include module type of struct
  include X509.Private_key
end

val sign
  :  Mirage_crypto.Hash.hash
  -> ?scheme:X509.Key_type.signature_scheme
  -> t
  -> [ `Digest of Cstruct.t | `Message of Cstruct.t ]
  -> string Or_error.t

val decode_der : contents:string -> t Or_error.t
val decode_pem : contents:string -> t Or_error.t
val of_pem_file : Filename.t -> t Deferred.Or_error.t
