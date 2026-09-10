let ( let* ) = Result.bind

type ecdsa = Ecdsa : {
  curve : (module Dsa_curves.S with type Dsa.pub = 'pub);
  pub : 'pub
} -> ecdsa

type t = [
  | `RSA of Mirage_crypto_pk.Rsa.pub
  | `ED25519 of Mirage_crypto_ec.Ed25519.pub
  | `ECDSA of ecdsa
]

module Asn_oid = Asn.OID

module Asn = struct
  open Asn_grammars
  open Asn.S
  open Mirage_crypto_pk

  let rsa_public_key =
    let f (n, e) =
      let n = Z_extra.of_octets_be n
      and e = Z_extra.of_octets_be e in
      match Rsa.pub ~e ~n with
      | Ok p -> p
      | Error (`Msg m) -> parse_error "bad RSA public key %s" m
    and g ({ Rsa.n; e } : Rsa.pub) = (Z_extra.to_octets_be n, Z_extra.to_octets_be e) in
    map f g @@
    sequence2
      (required ~label:"modulus"        unsigned_integer)
      (required ~label:"publicExponent" unsigned_integer)

  let (rsa_public_of_octets, rsa_public_to_octets) =
    projections_of Asn.der rsa_public_key

  let rsa_pub_of_octets, rsa_pub_to_octets = project_exn rsa_public_key

  let to_err = function
    | Ok r -> r
    | Error e ->
      parse_error "failed to decode public EC key %a"
        Mirage_crypto_ec.pp_error e

  let reparse_pk =
    let open Mirage_crypto_ec in
    let open Algorithm in
    function
    | (RSA      , cs) -> `RSA (rsa_pub_of_octets cs)
    | (ED25519  , cs) -> `ED25519 (to_err (Ed25519.pub_of_octets cs))
    | (EC_pub (module Curve), cs) ->
      let pub = Ecdsa {
        curve = (module Curve);
        pub = to_err (Curve.Dsa.pub_of_octets cs)
       } in
      `ECDSA pub
    | _ -> parse_error "unknown public key algorithm"

  let unparse_pk =
    let open Mirage_crypto_ec in
    let open Algorithm in
    function
    | `RSA pk    -> (RSA, rsa_pub_to_octets pk)
    | `ED25519 pk -> (ED25519, Ed25519.pub_to_octets pk)
    | `ECDSA (Ecdsa k) ->
      let (module Curve) = k.curve in
      (EC_pub (module Curve), Curve.Dsa.pub_to_octets k.pub)

  let pk_info_der =
    map reparse_pk unparse_pk @@
    sequence2
      (required ~label:"algorithm" Algorithm.identifier)
      (required ~label:"subjectPK" bit_string_octets)

  let (pub_info_of_octets, pub_info_to_octets) =
    projections_of Asn.der pk_info_der
end

let id k =
  let data = match k with
    | `RSA p -> Asn.rsa_public_to_octets p
    | `ED25519 pk -> Mirage_crypto_ec.Ed25519.pub_to_octets pk
    | `ECDSA Ecdsa k ->
      let (module Curve) = k.curve in
      Curve.Dsa.pub_to_octets k.pub
  in
  Digestif.(to_raw_string SHA1 (digest_string SHA1 data))

let fingerprint ?(hash = `SHA256) pub =
  let module Hash = (val (Digestif.module_of_hash' (hash :> Digestif.hash'))) in
  Hash.(to_raw_string (digest_string (Asn.pub_info_to_octets pub)))

let key_type = function
  | `RSA _ -> `RSA
  | `ED25519 _ -> `ED25519
  | `ECDSA Ecdsa k ->
    let (module C) = k.curve in
    `ECDSA ((module C) : Dsa_curves.t)

let sig_alg = function
  | `ECDSA _ -> `ECDSA
  | `RSA _ -> `RSA
  | `ED25519 _ -> `ED25519

let pp ppf k =
  Fmt.string ppf (Key_type.to_string (key_type k));
  Fmt.sp ppf ();
  Ohex.pp ppf (fingerprint k)

let hashed hash data =
  let module Hash = (val (Digestif.module_of_hash' hash)) in
  match data with
  | `Message msg -> Ok Hash.(to_raw_string (digest_string msg))
  | `Digest d ->
    let n = String.length d and m = Hash.digest_size in
    if n = m then Ok d else Error (`Msg "digested data of invalid size")

let trunc len data =
  if String.length data > len then
    String.sub data 0 len
  else
    data

let verify hash ?scheme ~signature key data =
  let open Mirage_crypto_ec in
  let ok_if_true p = if p then Ok () else Error (`Msg "bad signature") in
  let ecdsa_of_str cs =
    Result.map_error (function `Parse s -> `Msg s)
      (Algorithm.ecdsa_sig_of_octets cs)
  in
  let scheme = Key_type.opt_signature_scheme ?scheme (key_type key) in
  match key, scheme with
  | `RSA key, `RSA_PSS ->
    let module H = (val (Digestif.module_of_hash' hash)) in
    let module PSS = Mirage_crypto_pk.Rsa.PSS(H) in
    let* d = hashed hash data in
    ok_if_true (PSS.verify ~key ~signature (`Digest d))
  | `RSA key, `RSA_PKCS1 ->
    let hashp x = x = hash in
    let* d = hashed hash data in
    ok_if_true (Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key ~signature (`Digest d))
  | `ED25519 key, `ED25519 ->
    begin match data with
      | `Message msg -> ok_if_true (Ed25519.verify ~key signature ~msg)
      | `Digest _ -> Error (`Msg "Ed25519 only suitable with raw message")
    end
  | `ECDSA Ecdsa k, `ECDSA ->
    let* d = hashed hash data in
    let* s = ecdsa_of_str signature in
    let (module Curve) = k.curve in
    let key = k.pub in
    ok_if_true Curve.Dsa.(verify ~key s (trunc byte_length d))
  | _ -> Error (`Msg "invalid key and signature scheme combination")

let encode_der = Asn.pub_info_to_octets

let decode_der cs = Asn_grammars.err_to_msg (Asn.pub_info_of_octets cs)

let decode_pem cs =
  let* data = Pem.parse cs in
  let pks = List.filter (fun (t, _) -> String.equal "PUBLIC KEY" t) data in
  let* keys = Pem.foldM (fun (_, k) -> decode_der k) pks in
  Pem.exactly_one ~what:"public key" keys

let encode_pem v =
  Pem.unparse ~tag:"PUBLIC KEY" (encode_der v)
