open! Core
open! Async
open! Import

include module type of struct
  include X509.Distinguished_name
end

val to_string : t -> string
val decode_der : contents:string -> t Or_error.t
