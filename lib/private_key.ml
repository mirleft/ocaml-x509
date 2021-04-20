type ecdsa = [
  | `P224 of Mirage_crypto_ec.P224.Dsa.priv
  | `P256 of Mirage_crypto_ec.P256.Dsa.priv
  | `P384 of Mirage_crypto_ec.P384.Dsa.priv
  | `P521 of Mirage_crypto_ec.P521.Dsa.priv
]

type t = [
  ecdsa
  | `RSA of Mirage_crypto_pk.Rsa.priv
  | `ED25519 of Mirage_crypto_ec.Ed25519.priv
]

let public = function
  | `RSA priv -> `RSA (Mirage_crypto_pk.Rsa.pub_of_priv priv)
  | `ED25519 priv -> `ED25519 (Mirage_crypto_ec.Ed25519.pub_of_priv priv)
  | `P224 priv -> `P224 (Mirage_crypto_ec.P224.Dsa.pub_of_priv priv)
  | `P256 priv -> `P256 (Mirage_crypto_ec.P256.Dsa.pub_of_priv priv)
  | `P384 priv -> `P384 (Mirage_crypto_ec.P384.Dsa.pub_of_priv priv)
  | `P521 priv -> `P521 (Mirage_crypto_ec.P521.Dsa.pub_of_priv priv)

let keytype = function
  | `RSA _ -> `RSA
  | `ED25519 _ -> `ED25519
  | #ecdsa -> `ECDSA

module Asn = struct
  open Asn.S
  open Mirage_crypto_pk

  (* RSA *)
  let other_prime_infos =
    sequence_of @@
      (sequence3
        (required ~label:"prime"       integer)
        (required ~label:"exponent"    integer)
        (required ~label:"coefficient" integer))

  let rsa_private_key =
    let f (v, (n, (e, (d, (p, (q, (dp, (dq, (q', other))))))))) =
      match (v, other) with
      | (0, None) ->
        begin match Rsa.priv ~e ~d ~n ~p ~q ~dp ~dq ~q' with
          | Ok p -> p
          | Error (`Msg m) -> parse_error "bad RSA private key %s" m
        end
      | _         -> parse_error "multi-prime RSA keys not supported"
    and g { Rsa.e; d; n; p; q; dp; dq; q' } =
      (0, (n, (e, (d, (p, (q, (dp, (dq, (q', None))))))))) in
    map f g @@
    sequence @@
        (required ~label:"version"         int)
      @ (required ~label:"modulus"         integer)  (* n    *)
      @ (required ~label:"publicExponent"  integer)  (* e    *)
      @ (required ~label:"privateExponent" integer)  (* d    *)
      @ (required ~label:"prime1"          integer)  (* p    *)
      @ (required ~label:"prime2"          integer)  (* q    *)
      @ (required ~label:"exponent1"       integer)  (* dp   *)
      @ (required ~label:"exponent2"       integer)  (* dq   *)
      @ (required ~label:"coefficient"     integer)  (* qinv *)
     -@ (optional ~label:"otherPrimeInfos" other_prime_infos)

  (* For outside uses. *)
  let (rsa_private_of_cstruct, rsa_private_to_cstruct) =
    Asn_grammars.projections_of Asn.der rsa_private_key

  (* PKCS8 *)
  let (rsa_priv_of_cs, rsa_priv_to_cs) =
    Asn_grammars.project_exn rsa_private_key

  let ec_to_err = function
    | Ok x -> x
    | Error e -> parse_error "%a" Mirage_crypto_ec.pp_error e

  let ed25519_of_cs, ed25519_to_cs =
    Asn_grammars.project_exn octet_string

  let ec_private_key =
    let f (v, pk, nc, pub) =
      if v <> 1 then
        parse_error "bad version for ec Private key"
      else
        let curve = match nc with
          | Some c -> Some (Algorithm.curve_of_oid c)
          | None -> None
        in
        pk, curve, pub
    and g (pk, curve, pub) =
      let nc = match curve with
        | None -> None | Some c -> Some (Algorithm.curve_to_oid c)
      in
      (1, pk, nc, pub)
    in
    Asn.S.map f g @@
    sequence4
      (required ~label:"version" int) (* ecPrivkeyVer1(1) *)
      (required ~label:"privateKey" octet_string)
      (* from rfc5480: choice3, but only namedCurve is allowed in PKIX *)
      (optional ~label:"namedCurve" (explicit 0 oid))
      (optional ~label:"publicKey" (explicit 1 bit_string))

  let ec_of_cs, ec_to_cs =
    Asn_grammars.project_exn ec_private_key

  let reparse_ec_private curve priv =
    let open Mirage_crypto_ec in
    let open Rresult.R.Infix in
    match curve with
    | `SECP224R1 -> P224.Dsa.priv_of_cstruct priv >>| fun p -> `P224 p
    | `SECP256R1 -> P256.Dsa.priv_of_cstruct priv >>| fun p -> `P256 p
    | `SECP384R1 -> P384.Dsa.priv_of_cstruct priv >>| fun p -> `P384 p
    | `SECP521R1 -> P521.Dsa.priv_of_cstruct priv >>| fun p -> `P521 p

  (* external use (result) *)
  let ec_priv_of_cs =
    let open Rresult.R.Infix in
    let dec, _ = Asn_grammars.projections_of Asn.der ec_private_key in
    fun cs ->
      dec cs >>= fun (priv, curve, _pub) ->
      match curve with
      | None -> Error (`Parse "no curve provided")
      | Some c ->
        Rresult.R.(reword_error
                     (function `Msg e -> `Parse e)
                     (error_to_msg ~pp_error:Mirage_crypto_ec.pp_error
                        (reparse_ec_private c priv)))

  let ec_of_cs ?curve cs =
    let (priv, named_curve, _pub) = ec_of_cs cs in
    let nc =
      match curve, named_curve with
      | Some c, None -> c
      | None, Some c -> c
      | Some c, Some c' -> if c = c' then c else parse_error "conflicting curve"
      | None, None -> parse_error "unknown curve"
    in
    ec_to_err (reparse_ec_private nc priv)

  let ec_to_cs ?curve ?pub key = ec_to_cs (key, curve, pub)

  let reparse_private pk =
    match pk with
    | (0, Algorithm.RSA, cs) -> `RSA (rsa_priv_of_cs cs)
    | (0, Algorithm.ED25519, cs) ->
      let data = ed25519_of_cs cs in
      `ED25519 (ec_to_err (Mirage_crypto_ec.Ed25519.priv_of_cstruct data))
    | (0, Algorithm.EC_pub curve, cs) -> ec_of_cs ~curve cs
    | _ -> parse_error "unknown private key info"

  let unparse_private p =
    let open Mirage_crypto_ec in
    let open Algorithm in
    let alg, cs =
      match p with
      | `RSA pk -> RSA, rsa_priv_to_cs pk
      | `ED25519 pk -> ED25519, ed25519_to_cs (Ed25519.priv_to_cstruct pk)
      | `P224 pk -> EC_pub `SECP224R1, ec_to_cs (P224.Dsa.priv_to_cstruct pk)
      | `P256 pk -> EC_pub `SECP256R1, ec_to_cs (P256.Dsa.priv_to_cstruct pk)
      | `P384 pk -> EC_pub `SECP384R1, ec_to_cs (P384.Dsa.priv_to_cstruct pk)
      | `P521 pk -> EC_pub `SECP521R1, ec_to_cs (P521.Dsa.priv_to_cstruct pk)
    in
    (0, alg, cs)

  let private_key_info =
    map reparse_private unparse_private @@
    sequence3
      (required ~label:"version"             int)
      (required ~label:"privateKeyAlgorithm" Algorithm.identifier)
      (required ~label:"privateKey"          octet_string)
      (* TODO: there's an
         (optional ~label:"attributes" @@ implicit 0 (SET of Attributes)
         which are defined in X.501; but nobody seems to use them anyways *)

  let (private_of_cstruct, private_to_cstruct) =
    Asn_grammars.projections_of Asn.der private_key_info
end

let decode_der cs =
  Asn_grammars.err_to_msg (Asn.private_of_cstruct cs)

let encode_der = Asn.private_to_cstruct

let decode_pem cs =
  let open Rresult.R.Infix in
  Pem.parse cs >>= fun data ->
  let rsa_p (t, _) = String.equal "RSA PRIVATE KEY" t
  and ec_p (t, _) = String.equal "EC PRIVATE KEY" t
  and pk_p (t, _) = String.equal "PRIVATE KEY" t
  in
  let r, _ = List.partition rsa_p data
  and ec, _ = List.partition ec_p data
  and p, _ = List.partition pk_p data
  in
  Pem.foldM (fun (_, k) ->
      Asn_grammars.err_to_msg (Asn.rsa_private_of_cstruct k) >>| fun k ->
      `RSA k) r >>= fun k ->
  Pem.foldM (fun (_, k) ->
      Asn_grammars.err_to_msg (Asn.ec_priv_of_cs k)) ec >>= fun k' ->
  Pem.foldM (fun (_, k) ->
      Asn_grammars.err_to_msg (Asn.private_of_cstruct k)) p >>= fun k'' ->
  Pem.exactly_one ~what:"private key" (k @ k' @ k'')

let encode_pem p =
  Pem.unparse ~tag:"PRIVATE KEY" (Asn.private_to_cstruct p)
