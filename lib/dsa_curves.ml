module type Dsa = Mirage_crypto_ec.Dsa

module OIDs = Registry.ANSI_X9_62

module type S = sig
  val name : string
  val oid : Asn.oid
  module Dsa : Dsa
end

type t = (module S)

let curves, add_curve =
  let curves = ref [] in
  (fun () -> !curves),
  (fun c -> curves := c :: !curves)

let register name oid (module Dsa:Dsa) =
  let c = (module struct
    let name = String.lowercase_ascii name
    let oid = oid
    module Dsa = Dsa
  end : S) in
  add_curve c;
  c

let strings () =
  List.map (fun (module C : S) ->
    (C.name, `ECDSA (module C : S)))
    (curves ())

let find oid : t option =
  List.find_opt (fun (module C : S) -> C.oid = oid) (curves ())

let get_dsa c =
  let (module C : S) = c in
  (module C.Dsa : Dsa)

let get_name c =
  let (module C : S) = c in
  C.name

let get_oid c =
  let (module C : S) = c in
  C.oid

let of_name name =
  List.find_opt (fun (module C : S) -> C.name = name) (curves ())

let names () =
  List.map (fun (module C : S) -> C.name) (curves ())
