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
  let res =
    let hash_of_string = function
      | "md5" -> Some `MD5
      | "sha" | "sha1" -> Some `SHA1
      | "sha224" -> Some `SHA224
      | "sha256" -> Some `SHA256
      | "sha384" -> Some `SHA384
      | "sha512" -> Some `SHA512
      | _ -> None
    in
    match String.split_on_char ':' str with
    | [] -> Error (`Msg (Fmt.str "Invalid fingerprint %S" str))
    | [ fp ] -> Ok (`SHA256, fp)
    | hash :: rest ->
        match hash_of_string (String.lowercase_ascii hash) with
        | Some hash -> Ok (hash, String.concat "" rest)
        | None -> Error (`Msg (Fmt.str "Invalid hash algorithm: %S" hash))
  in
  match res with
  | Error _ as err -> err
  | Ok (hash, fp) ->
    try Ok (hash, Cstruct.of_string (Base64.decode_exn fp))
    with _ -> Error (`Msg (Fmt.str "Invalid base64 fingerprint value: %S" fp))

let none ?ip:_ ~host:_ _ = Ok None

let of_string str =
  let ( >>= ) = Result.bind in
  let ( >|= ) x f = Result.map f x in
  match String.split_on_char ':' str with
  | "key" :: tls_key_fingerprint ->
    let tls_key_fingerprint = String.concat ":" tls_key_fingerprint in
    of_fingerprint tls_key_fingerprint >|= fun (hash, fingerprint) ->
    (fun time -> server_key_fingerprint ~time ~hash ~fingerprint)
  | "cert" :: tls_cert_fingerprint ->
    let tls_cert_fingerprint = String.concat ":" tls_cert_fingerprint in
    of_fingerprint tls_cert_fingerprint >|= fun (hash, fingerprint) ->
    (fun time -> server_cert_fingerprint ~time ~hash ~fingerprint)
  | "trust-anchor" :: certs ->
    let certs = List.map Base64.decode certs in
    List.fold_left (fun a x ->
      match a, Result.(bind (map Cstruct.of_string x)) Certificate.decode_der with
      | Ok a, Ok x -> Ok (x :: a)
      | Error _ as err, _ -> err
      | Ok _, (Error _ as err) -> err) (Ok []) certs >>= fun certs ->
    Ok (fun time -> chain_of_trust ~time (List.rev certs))
  | [ "none" ] -> Ok (fun _ -> none)
  | _ -> Error (`Msg (Fmt.str "Invalid TLS authenticator: %S" str))
