let ( let* ) = Result.bind

type t = ?ip:Ipaddr.t -> host:[`host] Domain_name.t option ->
  Certificate.t list -> Validation.r

(* XXX
   * Authenticator just hands off a list of certs. Should be indexed.
   * *)
let chain_of_trust ~time ?crls ?(allowed_hashes = Validation.sha2) cas =
  let revoked = match crls with
    | None -> None
    | Some crls -> Some (Crl.is_revoked crls ~allowed_hashes)
  in
  fun ?ip ~host certificates ->
    Validation.verify_chain_of_trust ?ip ~host ~time ?revoked ~allowed_hashes
      ~anchors:cas certificates

let server_key_fingerprint ~time ~hash ~fingerprint =
  fun ?ip ~host certificates ->
    Validation.trust_key_fingerprint ?ip ~host ~time ~hash ~fingerprint certificates

let server_cert_fingerprint ~time ~hash ~fingerprint =
  fun ?ip ~host certificates ->
    Validation.trust_cert_fingerprint ?ip ~host ~time ~hash ~fingerprint certificates

let of_fingerprint str =
  let dec_b64 s =
    let* d =
      Result.map_error
        (function `Msg m ->
           `Msg (Fmt.str "Invalid base64 encoding in fingerprint (%s): %S" m s))
        (Base64.decode s)
    in
    Ok (Cstruct.of_string d)
  in
  let hash_of_string = function
    | "md5" -> Ok `MD5
    | "sha" | "sha1" -> Ok `SHA1
    | "sha224" -> Ok `SHA224
    | "sha256" -> Ok `SHA256
    | "sha384" -> Ok `SHA384
    | "sha512" -> Ok `SHA512
    | hash -> Error (`Msg (Fmt.str "Unknown hash algorithm %S" hash))
  in
  match String.split_on_char ':' str with
  | [ fp ] ->
    let* fp = dec_b64 fp in
    Ok (`SHA256, fp)
  | [ hash ; fp ] ->
    let* hash = hash_of_string (String.lowercase_ascii hash) in
    let* fp = dec_b64 fp in
    Ok (hash, fp)
  | _ -> Error (`Msg (Fmt.str "Invalid fingerprint %S" str))

let of_string str =
  match String.split_on_char ':' str with
  | "key-fp" :: tls_key_fingerprint ->
    let tls_key_fingerprint = String.concat ":" tls_key_fingerprint in
    let* hash, fingerprint = of_fingerprint tls_key_fingerprint in
    Ok (fun time -> server_key_fingerprint ~time ~hash ~fingerprint)
  | "cert-fp" :: tls_cert_fingerprint ->
    let tls_cert_fingerprint = String.concat ":" tls_cert_fingerprint in
    let* hash, fingerprint = of_fingerprint tls_cert_fingerprint in
    Ok (fun time -> server_cert_fingerprint ~time ~hash ~fingerprint)
  | "trust-anchor" :: certs ->
    let* anchors =
      List.fold_left (fun acc s ->
          let* acc = acc in
          let* der = Base64.decode s in
          let* cert = Certificate.decode_der (Cstruct.of_string der) in
          Ok (cert :: acc))
        (Ok []) certs
    in
    Ok (fun time -> chain_of_trust ~time (List.rev anchors))
  | [ "none" ] -> Ok (fun _ ?ip:_ ~host:_ _ -> Ok None)
  | _ -> Error (`Msg (Fmt.str "Invalid TLS authenticator: %S" str))
