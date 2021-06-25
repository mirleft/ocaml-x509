open! Core
open! Async
open! Import

include module type of struct
  include X509.Authenticator
end

module Param : sig
  type t

  val ca_file
    :  ?allowed_hashes:Mirage_crypto.Hash.hash list
    -> ?crls:Filename.t
    -> Filename.t
    -> unit
    -> t

  val ca_dir
    :  ?allowed_hashes:Mirage_crypto.Hash.hash list
    -> ?crls:Filename.t
    -> Filename.t
    -> unit
    -> t

  (** The fingerprint can be collected from a browser or by invoking an openssl command
      like 'openssl x509 -in <pem_file> -noout -fingerprint -sha256' *)
  val cert_fingerprints
    :  Mirage_crypto.Hash.hash
    -> ([ `host ] Domain_name.t * string) list
    -> t

  (** Async programs often don't use [Ptime_clock], so this is provided as a convenience
      function. Relies on [Unix.gettimeofday]. *)
  val time : unit -> Ptime.t option

  val to_authenticator
    :  time:(unit -> Ptime.t option)
    -> t
    -> X509.Authenticator.t Deferred.Or_error.t
end
