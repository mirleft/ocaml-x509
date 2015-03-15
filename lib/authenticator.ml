type res = [
  | `Ok   of Certificate.certificate option
  | `Fail of Certificate.certificate_failure
]

type t = ?host:Certificate.host -> Certificate.certificate list -> res

(* XXX
   * Authenticator just hands off a list of certs. Should be indexed.
   * *)
(* XXX
   * Authenticator authenticates against time it was *created* at, not at the moment of
   * authentication. This has repercussions to long-lived authenticators; reconsider.
   * *)
let chain_of_trust ?time cas =
  let cas = Certificate.valid_cas ?time cas in
  fun ?host certificates ->
    Certificate.verify_chain_of_trust ?host ?time ~anchors:cas certificates

let server_fingerprint ?time ~hash ~fingerprints =
  fun ?host certificates ->
    Certificate.trust_fingerprint ?host ?time ~hash ~fingerprints certificates

let null ?host:_ _ = `Ok None

open Sexplib

let t_of_sexp = function
  | Sexp.Atom "NULL" -> null
  | sexp ->
    Conv.of_sexp_error "Authenticator.t_of_sexp: atom 'NULL' needed" sexp

let sexp_of_t _ = Sexp.Atom "NULL"
