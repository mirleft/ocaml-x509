type t = [ `RSA | `ED25519 | `P224 | `P256 | `P384 | `P521  ]

let strings =
  [ ("rsa", `RSA) ; ("ed25519", `ED25519) ; ("p224", `P224) ;
    ("p256", `P256) ; ("p384", `P384) ; ("p521", `P521) ]

let to_string kt = fst (List.find (fun (_, k) -> kt = k) strings)

let of_string s =
  match List.assoc_opt (String.lowercase_ascii s) strings with
  | Some kt -> Ok kt
  | None ->
    Rresult.R.error_msgf "unkown key type %s, supported are %a"
      s Fmt.(list ~sep:(unit ", ") string) (List.map fst strings)

