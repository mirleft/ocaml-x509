type t = [ `RSA | `ED25519 | `ECDSA of Dsa_curves.t]

let strings () =
  ("rsa", `RSA) :: ("ed25519", `ED25519) :: (Dsa_curves.strings ())

let to_string = function
  | `RSA -> "rsa"
  | `ED25519 -> "ed25519"
  | `ECDSA c -> Dsa_curves.get_name c

let of_string s =
  match String.lowercase_ascii s with
  | "rsa" -> Ok `RSA
  | "ed25519" -> Ok `ED25519
  | s -> match Dsa_curves.of_name s with
    | Some c -> Ok (`ECDSA c)
    | None ->
      Error (`Msg (Fmt.str "unkown key type %s, supported are %a"
        s Fmt.(list ~sep:(any ", ") string) (List.map fst (strings ()))))

let pp ppf t = Fmt.string ppf (to_string t)

type signature_scheme = [ `RSA_PSS | `RSA_PKCS1 | `ECDSA | `ED25519 ]

let signature_scheme_to_string = function
  | `RSA_PSS -> "RSA-PSS"
  | `RSA_PKCS1 -> "RSA-PKCS1"
  | `ECDSA -> "ECDSA"
  | `ED25519 -> "ED25519"

let pp_signature_scheme ppf s = Fmt.string ppf (signature_scheme_to_string s)

let supports_signature_scheme key_typ scheme =
  match key_typ, scheme with
  | `RSA, (`RSA_PSS | `RSA_PKCS1) -> true
  | `ED25519, `ED25519 -> true
  | `ECDSA _, `ECDSA -> true
  | _ -> false

let opt_signature_scheme ?scheme kt =
  match scheme with
  | Some x -> x
  | None -> match kt with
    | `RSA -> `RSA_PSS
    | `ED25519 -> `ED25519
    | `ECDSA _ -> `ECDSA

(* the default of RSA keys should be PSS, but most deployed certificates still
   use PKCS1 (and this library uses pkcs1 by default as well) *)
let x509_default_scheme = function
  | `RSA -> `RSA_PKCS1
  | x -> opt_signature_scheme x
