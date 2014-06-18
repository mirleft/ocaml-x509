
module Pem : sig
  val parse : Cstruct.t -> (string * Cstruct.t) list
end

module Cert : sig
  type t = Certificate.certificate
  val of_pem_cstruct  : Cstruct.t -> t list
  val of_pem_cstruct1 : Cstruct.t -> t
end

module PK : sig
  type t = Nocrypto.RSA.priv
  val of_pem_cstruct  : Cstruct.t -> t list
  val of_pem_cstruct1 : Cstruct.t -> t
end

module Validator : sig

  type t
  type res = [ `Ok | `Fail of Certificate.certificate_failure ]

  val validate : t -> ?host:Certificate.host -> Certificate.stack -> res

  val chain_of_trust : ?time:float -> Cert.t list -> t
  val null : t
end
