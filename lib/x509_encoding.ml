
let cs_of_cert = X509_certificate.cs_of_cert

let cs_of_distinguished_name = Asn_grammars.Name.name_to_cstruct

let parse = X509_certificate.parse_certificate

let parse_signing_request = X509_ca.parse_signing_request

let cs_of_signing_request = X509_ca.cs_of_signing_request

let pkcs1_digest_info_of_cstruct : Cstruct.t -> (Nocrypto.Hash.hash * Cstruct.t) option =
  Asn_grammars.pkcs1_digest_info_of_cstruct

let pkcs1_digest_info_to_cstruct : (Nocrypto.Hash.hash * Cstruct.t) -> Cstruct.t =
  Asn_grammars.pkcs1_digest_info_to_cstruct

let rsa_public_to_cstruct : Nocrypto.Rsa.pub -> Cstruct.t =
  Asn_grammars.PK.rsa_public_to_cstruct

let rsa_public_of_cstruct : Cstruct.t -> Nocrypto.Rsa.pub option =
  Asn_grammars.PK.rsa_public_of_cstruct

let crl_to_cstruct : X509_crl.c -> Cstruct.t =
  X509_crl.crl_to_cstruct

let crl_of_cstruct : Cstruct.t -> X509_crl.c option =
  X509_crl.crl_of_cstruct

module Pem = X509_pem

