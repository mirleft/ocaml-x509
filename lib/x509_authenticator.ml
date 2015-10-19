
open X509_certificate

type a = ?host:host -> t list -> Validation.result

(* XXX
   * Authenticator just hands off a list of certs. Should be indexed.
   * *)
(* XXX
   * Authenticator authenticates against time it was *created* at, not at the moment of
   * authentication. This has repercussions to long-lived authenticators; reconsider.
   * *)
let chain_of_trust ?time cas =
  let cas = Validation.valid_cas ?time cas in
  fun ?host certificates ->
    Validation.verify_chain_of_trust ?host ?time ~anchors:cas certificates

let server_cert_fingerprint ?time ~hash ~fingerprints =
  fun ?host certificates ->
    Validation.trust_cert_fingerprint ?host ?time ~hash ~fingerprints certificates

let null ?host:_ _ = `Ok None

open Sexplib

let a_of_sexp = function
  | Sexp.Atom "NULL" -> null
  | sexp ->
    Conv.of_sexp_error "Authenticator.t_of_sexp: atom 'NULL' needed" sexp

let sexp_of_a _ = Sexp.Atom "NULL"
