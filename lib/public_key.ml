type t = [
  | `RSA    of Mirage_crypto_pk.Rsa.pub
  | `ED25519 of Cstruct.t
  | `P224 of Mirage_crypto_ec.P224.Dsa.pub
  | `P256 of Mirage_crypto_ec.P256.Dsa.pub
  | `P384 of Mirage_crypto_ec.P384.Dsa.pub
  | `P521 of Mirage_crypto_ec.P521.Dsa.pub
  | `EC_pub of Asn.oid * Cstruct.t
]

module Asn_oid = Asn.OID

module Asn = struct
  open Asn_grammars
  open Asn.S
  open Mirage_crypto_pk

  let rsa_public_key =
    let f (n, e) = match Rsa.pub ~e ~n with
      | Ok p -> p
      | Error (`Msg m) -> parse_error "bad RSA public key %s" m
    and g ({ Rsa.n; e } : Rsa.pub) = (n, e) in
    map f g @@
    sequence2
      (required ~label:"modulus"        integer)
      (required ~label:"publicExponent" integer)

  let (rsa_public_of_cstruct, rsa_public_to_cstruct) =
    projections_of Asn.der rsa_public_key

  let rsa_pub_of_cs, rsa_pub_to_cs = project_exn rsa_public_key

  let to_err = function
    | Ok r -> r
    | Error e ->
      parse_error "failed to decode public EC key %a"
        Mirage_crypto_ec.pp_error e

  let reparse_pk = function
    | (Algorithm.RSA      , cs) -> `RSA (rsa_pub_of_cs cs)
    | (Algorithm.ED25519  , cs) -> `ED25519 cs
    | (Algorithm.EC_pub `SECP224R1, cs) ->
      `P224 (to_err (Mirage_crypto_ec.P224.Dsa.pub_of_cstruct cs))
    | (Algorithm.EC_pub `SECP256R1, cs) ->
      `P256 (to_err (Mirage_crypto_ec.P256.Dsa.pub_of_cstruct cs))
    | (Algorithm.EC_pub `SECP384R1, cs) ->
      `P384 (to_err (Mirage_crypto_ec.P384.Dsa.pub_of_cstruct cs))
    | (Algorithm.EC_pub `SECP521R1, cs) ->
      `P521 (to_err (Mirage_crypto_ec.P521.Dsa.pub_of_cstruct cs))
    | (Algorithm.EC_pub (`Other id), cs)  -> `EC_pub (id, cs)
    | _ -> parse_error "unknown public key algorithm"

  let unparse_pk = function
    | `RSA pk    -> (Algorithm.RSA, rsa_pub_to_cs pk)
    | `ED25519 pk -> (Algorithm.ED25519, pk)
    | `P224 pk ->
      (Algorithm.EC_pub `SECP224R1, Mirage_crypto_ec.P224.Dsa.pub_to_cstruct pk)
    | `P256 pk ->
      (Algorithm.EC_pub `SECP256R1, Mirage_crypto_ec.P256.Dsa.pub_to_cstruct pk)
    | `P384 pk ->
      (Algorithm.EC_pub `SECP384R1, Mirage_crypto_ec.P384.Dsa.pub_to_cstruct pk)
    | `P521 pk ->
      (Algorithm.EC_pub `SECP521R1, Mirage_crypto_ec.P521.Dsa.pub_to_cstruct pk)
    | `EC_pub (id, cs) -> (Algorithm.EC_pub (`Other id), cs)

  let pk_info_der =
    map reparse_pk unparse_pk @@
    sequence2
      (required ~label:"algorithm" Algorithm.identifier)
      (required ~label:"subjectPK" bit_string_cs)

  let (pub_info_of_cstruct, pub_info_to_cstruct) =
    projections_of Asn.der pk_info_der
end

let id k =
  let data = match k with
    | `RSA p -> Asn.rsa_public_to_cstruct p
    | `ED25519 p -> p
    | `P224 pk -> Mirage_crypto_ec.P224.Dsa.pub_to_cstruct pk
    | `P256 pk -> Mirage_crypto_ec.P256.Dsa.pub_to_cstruct pk
    | `P384 pk -> Mirage_crypto_ec.P384.Dsa.pub_to_cstruct pk
    | `P521 pk -> Mirage_crypto_ec.P521.Dsa.pub_to_cstruct pk
    | `EC_pub (_, cs) -> cs
  in
  Mirage_crypto.Hash.digest `SHA1 data

let fingerprint ?(hash = `SHA256) pub =
  Mirage_crypto.Hash.digest hash (Asn.pub_info_to_cstruct pub)

let pp ppf k =
  (match k with
   | `RSA _ -> Fmt.string ppf "RSA "
   | `ED25519 _ -> Fmt.string ppf "ED25519 "
   | `P224 _ -> Fmt.string ppf "P224 "
   | `P256 _ -> Fmt.string ppf "P256 "
   | `P384 _ -> Fmt.string ppf "P384 "
   | `P521 _ -> Fmt.string ppf "P521 "
   | `EC_pub (oid, _) -> Fmt.pf ppf "EC %a" Asn_oid.pp oid);
  Cstruct.hexdump_pp ppf (fingerprint k)

let encode_der = Asn.pub_info_to_cstruct

let decode_der cs = Asn_grammars.err_to_msg (Asn.pub_info_of_cstruct cs)

let decode_pem cs =
  let open Rresult.R.Infix in
  Pem.parse cs >>= fun data ->
  let pks = List.filter (fun (t, _) -> String.equal "PUBLIC KEY" t) data in
  Pem.foldM (fun (_, k) -> decode_der k) pks >>=
  Pem.exactly_one ~what:"public key"

let encode_pem v =
  Pem.unparse ~tag:"PUBLIC KEY" (encode_der v)
