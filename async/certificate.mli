open! Core
open! Async
open! Import

include module type of struct
  include X509.Certificate
end

val decode_pem_multiple : contents:string -> t list Or_error.t
val decode_pem : contents:string -> t Or_error.t
val decode_der : contents:string -> t Or_error.t
val of_pem_file : Filename.t -> t list Deferred.Or_error.t
val of_pem_directory : directory:Filename.t -> t list Deferred.Or_error.t
