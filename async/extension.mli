open! Core
open! Async
open! Import

include module type of struct
  include X509.Extension
end

val to_string : t -> string
