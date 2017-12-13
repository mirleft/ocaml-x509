open Asn_grammars.CRL
include X509_crl_types

type c = {
  raw : Cstruct.t ;
  asn : Asn_grammars.CRL.t ;
}

let crl_to_cstruct { raw ; _ } = raw

let crl_of_cstruct raw =
  match crl_of_cstruct raw with
  | None -> None
  | Some asn -> Some { raw ; asn }

let issuer { asn ; _ } = asn.tbs_crl.issuer

let this_update { asn ; _ } = asn.tbs_crl.this_update

let next_update { asn ; _ } = asn.tbs_crl.next_update

let extensions { asn ; _ } = asn.tbs_crl.extensions

let revoked_certificates { asn ; _ } = asn.tbs_crl.revoked_certs

let crl_number { asn ; _ } =
  X509_common.List_ext.map_find asn.tbs_crl.extensions ~f:(fun (_, ext) ->
      match ext with
      | `CRL_number x -> Some x
      | _ -> None)

let validate { raw ; asn } pub =
  let tbs_raw = X509_certificate.raw_cert_hack raw asn.signature_val in
  X509_certificate.validate_raw_signature tbs_raw asn.signature_algo asn.signature_val pub

let verify ({ asn ; _ } as crl) ?time cert =
  Asn_grammars.Name.equal asn.tbs_crl.issuer (X509_certificate.subject cert) &&
  (match time with
   | None -> true
   | Some x -> Ptime.is_later ~than:asn.tbs_crl.this_update x &&
               match asn.tbs_crl.next_update with
               | None -> true
               | Some y -> Ptime.is_earlier ~than:y x) &&
  validate crl (X509_certificate.public_key cert)

let reason revoked =
  X509_common.List_ext.map_find revoked.extensions ~f:(fun (_, ext) ->
      match ext with
      | `Reason x -> Some x
      | _ -> None)

let is_revoked crls ~issuer:super ~cert =
  List.exists (fun crl ->
      if
        Asn_grammars.Name.equal (X509_certificate.subject super) (issuer crl) &&
        validate crl (X509_certificate.public_key super)
      then
        try
          let entry = List.find
              (fun r -> Z.equal (X509_certificate.serial cert) r.serial)
              (revoked_certificates crl)
          in
          match reason entry with
          | None -> true
          | Some `Remove_from_CRL -> false
          | Some _ -> true
        with Not_found -> false
      else
        false)
    crls

let sign_tbs (tbs : tBS_CRL) key =
  let tbs_raw = tbs_CRL_to_cstruct tbs in
  let digest = match Asn_grammars.Algorithm.to_signature_algorithm tbs.signature with
    | Some (_, h) -> h
    | _ -> invalid_arg "couldn't parse signature algorithm"
  in
  let signature_val = X509_ca.raw_sign tbs_raw digest key in
  let asn = { tbs_crl = tbs ; signature_algo = tbs.signature ; signature_val } in
  let raw = Asn_grammars.CRL.crl_to_cstruct asn in
  { asn ; raw }

let revoke
    ?(digest = `SHA256)
    ~issuer
    ~this_update ?next_update
    ?(extensions = [])
    revoked_certs
    key =
  let signature =
    Asn_grammars.Algorithm.of_signature_algorithm
      (X509_certificate.private_key_to_keytype key) digest
  in
  let tbs_crl = {
    version = `V2 ;
    signature ;
    issuer ;
    this_update ; next_update ;
    revoked_certs ;
    extensions
  }
  in
  sign_tbs tbs_crl key

let revoke_certificates revoked ~this_update ?next_update ({ asn ; _ } as crl) key =
  let tbs = asn.tbs_crl in
  let extensions = match crl_number crl with
    | None -> (false, `CRL_number 0) :: tbs.extensions
    | Some x -> (false, `CRL_number (succ x)) ::
                List.filter (function (_, `CRL_number _) -> false | _ -> true)
                  tbs.extensions
  in
  let tbs = {
    tbs with revoked_certs = tbs.revoked_certs @ revoked ;
             this_update ; next_update ;
             extensions
  }
  in
  sign_tbs tbs key

let revoke_certificate revoked ~this_update ?next_update crl key =
  revoke_certificates [revoked] ~this_update ?next_update crl key
