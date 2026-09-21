let ( let* ) = Result.bind

type ecdsa = Ecdsa : {
  curve : (module Dsa_curves.S with type Dsa.priv = 'priv);
  priv : 'priv
} -> ecdsa

type t = [
  | `RSA of Mirage_crypto_pk.Rsa.priv
  | `ED25519 of Mirage_crypto_ec.Ed25519.priv
  | `ECDSA of ecdsa
]

let key_type = function
  | `RSA _ -> `RSA
  | `ED25519 _ -> `ED25519
  | `ECDSA Ecdsa k ->
    let (module C) = k.curve in
    `ECDSA ((module C) : Dsa_curves.t)

let generate ?seed ?(bits = 4096) typ =
  let g = match seed with
    | None -> None
    | Some seed -> Some Mirage_crypto_rng.(create ~seed (module Fortuna))
  in
  match typ with
  | `RSA -> `RSA (Mirage_crypto_pk.Rsa.generate ?g ~bits ())
  | `ED25519 -> `ED25519 (fst (Mirage_crypto_ec.Ed25519.generate ?g ()))
  | `ECDSA (module C : Dsa_curves.S) ->
    let priv = Ecdsa {
      curve = (module C);
      priv = (fst (C.Dsa.generate ?g ()))
     } in
    `ECDSA priv

let of_octets data =
  let open Mirage_crypto_ec in
  let ec_err e =
    Result.map_error
      (fun e -> `Msg (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
      e
  in
  function
  | `RSA -> Error (`Msg "cannot decode an RSA key")
  | `ED25519 ->
    let* k = ec_err (Ed25519.priv_of_octets data) in
    Ok (`ED25519 k)
  | `ECDSA (module C : Dsa_curves.S) ->
    let* k = ec_err (C.Dsa.priv_of_octets data) in
    let priv = Ecdsa {
      curve = (module C);
      priv = k
    } in
    Ok (`ECDSA priv)

let of_string ?seed_or_data ?bits typ data =
  match seed_or_data with
  | None ->
    begin match typ with
      | `RSA -> Ok (generate ~seed:data ?bits `RSA)
      | _ ->
        let* data = Base64.decode data in
        of_octets data typ
    end
  | Some `Seed ->
    Ok (generate ~seed:data ?bits typ)
  | Some `Data ->
    let* data = Base64.decode data in
    of_octets data typ

let public = function
  | `RSA priv -> `RSA (Mirage_crypto_pk.Rsa.pub_of_priv priv)
  | `ED25519 priv -> `ED25519 (Mirage_crypto_ec.Ed25519.pub_of_priv priv)
  | `ECDSA Ecdsa k  ->
    let (module Curve) = k.curve in
    let pub = Public_key.Ecdsa {
      curve = (module Curve);
      pub = Curve.Dsa.pub_of_priv k.priv
     } in
    `ECDSA pub

let sign hash ?scheme key data =
  let open Mirage_crypto_ec in
  let hashed () = Public_key.hashed hash data
  and ecdsa_to_str s = Algorithm.ecdsa_sig_to_octets s
  in
  let scheme = Key_type.opt_signature_scheme ?scheme (key_type key) in
  try
    match key, scheme with
    | `RSA key, `RSA_PSS ->
      let module H = (val (Digestif.module_of_hash' hash)) in
      let module PSS = Mirage_crypto_pk.Rsa.PSS(H) in
      let* d = hashed () in
      Ok (PSS.sign ~key (`Digest d))
    | `RSA key, `RSA_PKCS1 ->
      let* d = hashed () in
      Ok (Mirage_crypto_pk.Rsa.PKCS1.sign ~key ~hash (`Digest d))
    | `ED25519 key, `ED25519 ->
      begin match data with
        | `Message m -> Ok (Ed25519.sign ~key m)
        | `Digest _ -> Error (`Msg "Ed25519 only suitable with raw message")
      end
    | `ECDSA (Ecdsa k), `ECDSA ->
      let* d = hashed () in
      let (module Curve) = k.curve in
      let key = k.priv in
      Ok (ecdsa_to_str (Curve.Dsa.(sign ~key (Public_key.trunc byte_length d))))
    | _ -> Error (`Msg "invalid key and signature scheme combination")
  with
  | Mirage_crypto_pk.Rsa.Insufficient_key ->
    Error (`Msg "RSA key of insufficient length")
  | Message_too_long -> Error (`Msg "message too long")

module Asn = struct
  open Asn.S
  open Mirage_crypto_pk

  (* RSA *)
  let other_prime_infos =
    sequence_of @@
      (sequence3
        (required ~label:"prime"       unsigned_integer)
        (required ~label:"exponent"    unsigned_integer)
        (required ~label:"coefficient" unsigned_integer))

  let rsa_private_key =
    let integer = map Z_extra.of_octets_be Z_extra.to_octets_be unsigned_integer in
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
  let (rsa_private_of_octets, rsa_private_to_octets) =
    Asn_grammars.projections_of Asn.der rsa_private_key

  (* PKCS8 *)
  let (rsa_priv_of_str, rsa_priv_to_str) =
    Asn_grammars.project_exn rsa_private_key

  let ec_to_err = function
    | Ok x -> x
    | Error e -> parse_error "%a" Mirage_crypto_ec.pp_error e

  let ed25519_of_str, ed25519_to_str =
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

  let ec_of_str, ec_to_str =
    Asn_grammars.project_exn ec_private_key

  let reparse_ec_private (curve : Dsa_curves.t) priv =
    let (module Curve) = curve in
    let* p = Curve.Dsa.priv_of_octets priv in
    let k = Ecdsa {
      curve = (module Curve);
      priv = p
     } in
    Ok (`ECDSA k)

  (* external use (result) *)
  let ec_priv_of_str =
    let dec, _ = Asn_grammars.projections_of Asn.der ec_private_key in
    fun cs ->
      let* priv, curve, _pub = dec cs in
      match curve with
      | None -> Error (`Parse "no curve provided")
      | Some c ->
        Result.map_error
          (fun e -> `Parse (Fmt.to_to_string Mirage_crypto_ec.pp_error e))
          (reparse_ec_private c priv)

  let ec_of_str ?curve cs =
    let (priv, named_curve, _pub) = ec_of_str cs in
    let nc =
      match curve, named_curve with
      | Some c, None -> c
      | None, Some c -> c
      | Some c, Some c' -> if c = c' then c else parse_error "conflicting curve"
      | None, None -> parse_error "unknown curve"
    in
    ec_to_err (reparse_ec_private nc priv)

  let ec_to_str ?curve ?pub key = ec_to_str (key, curve, pub)

  let reparse_private pk =
    match pk with
    | (0, Algorithm.RSA, cs) -> `RSA (rsa_priv_of_str cs)
    | (0, Algorithm.ED25519, cs) ->
      let data = ed25519_of_str cs in
      `ED25519 (ec_to_err (Mirage_crypto_ec.Ed25519.priv_of_octets data))
    | (0, Algorithm.EC_pub curve, cs) -> ec_of_str ~curve cs
    | _ -> parse_error "unknown private key info"

  let unparse_private p =
    let open Mirage_crypto_ec in
    let open Algorithm in
    let alg, cs =
      match p with
      | `RSA pk -> RSA, rsa_priv_to_str pk
      | `ED25519 pk -> ED25519, ed25519_to_str (Ed25519.priv_to_octets pk)
      | `ECDSA Ecdsa k ->
        let (module Curve) = k.curve in
        EC_pub (module Curve), ec_to_str (Curve.Dsa.priv_to_octets k.priv)
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

  let (private_of_octets, private_to_octets) =
    Asn_grammars.projections_of Asn.der private_key_info
end

let decode_der cs =
  Asn_grammars.err_to_msg (Asn.private_of_octets cs)

let encode_der = Asn.private_to_octets

let decode_pem cs =
  let* data = Pem.parse cs in
  let rsa_p (t, _) = String.equal "RSA PRIVATE KEY" t
  and ec_p (t, _) = String.equal "EC PRIVATE KEY" t
  and pk_p (t, _) = String.equal "PRIVATE KEY" t
  in
  let r, _ = List.partition rsa_p data
  and ec, _ = List.partition ec_p data
  and p, _ = List.partition pk_p data
  in
  let* k =
    Pem.foldM (fun (_, k) ->
        let* k = Asn_grammars.err_to_msg (Asn.rsa_private_of_octets k) in
        Ok (`RSA k)) r
  in
  let* k' =
    Pem.foldM (fun (_, k) ->
        Asn_grammars.err_to_msg (Asn.ec_priv_of_str k)) ec
  in
  let* k'' =
    Pem.foldM (fun (_, k) ->
        Asn_grammars.err_to_msg (Asn.private_of_octets k)) p
  in
  Pem.exactly_one ~what:"private key" (k @ k' @ k'')

let encode_pem p =
  Pem.unparse ~tag:"PRIVATE KEY" (Asn.private_to_octets p)
