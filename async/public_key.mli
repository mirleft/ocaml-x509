open! Core
open! Async
open! Import

include module type of struct
  include X509.Public_key
end

val verify
  :  Mirage_crypto.Hash.hash
  -> ?scheme:X509.Key_type.signature_scheme
  -> signature:string
  -> t
  -> [ `Digest of string | `Message of string ]
  -> unit Or_error.t

val decode_der : contents:string -> t Or_error.t
val decode_pem : contents:string -> t Or_error.t
