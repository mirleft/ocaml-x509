open! Core
open! Async
open! Import

include module type of struct
  include X509.Signing_request
end

val decode_der : ?allowed_hashes:Mirage_crypto.Hash.hash list -> string -> t Or_error.t
val decode_pem : string -> t Or_error.t

val create
  :  X509.Distinguished_name.t
  -> ?digest:Mirage_crypto.Hash.hash
  -> ?extensions:Ext.t
  -> X509.Private_key.t
  -> t Or_error.t

val sign
  :  ?allowed_hashes:Mirage_crypto.Hash.hash list
  -> ?digest:Mirage_crypto.Hash.hash
  -> ?serial:Z.t
  -> ?extensions:X509.Extension.t
  -> X509.Signing_request.t
  -> X509.Private_key.t
  -> X509.Distinguished_name.t
  -> valid_from:Ptime.t
  -> valid_until:Ptime.t
  -> X509.Certificate.t Or_error.t
