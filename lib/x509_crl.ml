open Asn_grammars.CRL
include X509_crl_types

type t = {
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
