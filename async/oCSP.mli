open! Core
open! Async
open! Import

include module type of struct
  include X509.OCSP
end

module Request : sig
  include module type of struct
    include X509.OCSP.Request
  end

  val create
    :  ?certs:X509.Certificate.t list
    -> ?digest:Mirage_crypto.Hash.hash
    -> ?requestor_name:X509.General_name.b
    -> ?key:X509.Private_key.t
    -> cert_id list
    -> t Or_error.t

  val decode_der : contents:string -> t Or_error.t
end

module Response : sig
  include module type of struct
    include X509.OCSP.Response
  end

  val create_success
    :  ?digest:Mirage_crypto.Hash.hash
    -> ?certs:X509.Certificate.t list
    -> ?response_extensions:X509.Extension.t
    -> X509.Private_key.t
    -> responder_id
    -> Ptime.t
    -> single_response list
    -> t Or_error.t

  val responses : t -> single_response list Or_error.t
  val decode_der : contents:string -> t Or_error.t
end
