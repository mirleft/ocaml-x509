open! Core
open! Async
open! Import
include X509.Authenticator

module Param = struct
  module Chain_of_trust = struct
    type t =
      { trust_anchors : [ `File of Filename.t | `Directory of Filename.t ]
      ; allowed_hashes : Mirage_crypto.Hash.hash list option
      ; crls : Filename.t option
      }

    let to_certs = function
      | `File file -> Certificate.of_pem_file file
      | `Directory directory -> Certificate.of_pem_directory ~directory
    ;;
  end

  type t =
    | Chain_of_trust of Chain_of_trust.t
    | Cert_fingerprints of
        Mirage_crypto.Hash.hash * ([ `host ] Domain_name.t * string) list

  let ca_file ?allowed_hashes ?crls filename () =
    let trust_anchors = `File filename in
    Chain_of_trust { trust_anchors; allowed_hashes; crls }
  ;;

  let ca_dir ?allowed_hashes ?crls directory_name () =
    let trust_anchors = `Directory directory_name in
    Chain_of_trust { trust_anchors; allowed_hashes; crls }
  ;;

  let cert_fingerprints hash fingerprints = Cert_fingerprints (hash, fingerprints)

  let cleanup_fingerprint fingerprint =
    let known_delimiters = [ ':'; ' ' ] in
    String.filter fingerprint ~f:(fun c ->
      not (List.exists known_delimiters ~f:(Char.equal c)))
    |> Cstruct.of_hex
  ;;

  let of_cas ~time ({ trust_anchors; allowed_hashes; crls } : Chain_of_trust.t) =
    let open Deferred.Or_error.Let_syntax in
    let%bind cas = Chain_of_trust.to_certs trust_anchors in
    let%map crls =
      match crls with
      | Some directory ->
        let%map crls = CRL.of_pem_dir ~directory in
        Some crls
      | None -> return None
    in
    X509.Authenticator.chain_of_trust ?allowed_hashes ?crls ~time cas
  ;;

  let cert_fingerprint ~time hash fingerprints =
    let fingerprints =
      List.map fingerprints ~f:(Tuple.T2.map_snd ~f:cleanup_fingerprint)
    in
    X509.Authenticator.server_cert_fingerprint ~time ~hash ~fingerprints
  ;;

  let time = Fn.compose Ptime.of_float_s Unix.gettimeofday

  let to_authenticator ~time param =
    match param with
    | Chain_of_trust chain_of_trust -> of_cas ~time chain_of_trust
    | Cert_fingerprints (hash, fingerprints) ->
      cert_fingerprint ~time hash fingerprints |> Deferred.Or_error.return
  ;;
end
