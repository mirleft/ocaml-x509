module Asn = struct
  open Asn.S
  open Asn_grammars


  let digest_info =
    sequence2
      (required ~label:"digestAlgorithm" Algorithm.identifier)
      (required ~label:"digest" octet_string)

  let encrypted_content_info =
    sequence3
      (required ~label:"contentType" oid)
      (required ~label:"contentEncryptionAlgorithm" Algorithm.identifier)
      (optional ~label:"encryptedContent" @@ implicit 0 octet_string)

  type encrypted_data = Asn.oid * Algorithm.t * Cstruct.t option

  let encrypted_data : encrypted_data t =
    map (fun (_, c) -> c) (fun c -> 0, c) @@
    sequence2
      (required ~label:"version" int)
      (required ~label:"encryptedContentInfo" encrypted_content_info)


  (*  SignedData ::= SEQUENCE {
   *    version Version,
   *    digestAlgorithms DigestAlgorithmIdentifiers,
   *    contentInfo ContentInfo,
   *    certificates
   *       [0] IMPLICIT ExtendedCertificatesAndCertificates
   *         OPTIONAL,
   *    crls
   *      [1] IMPLICIT CertificateRevocationLists OPTIONAL,
   *    signerInfos SignerInfos }
   * 
   *  DigestAlgorithmIdentifiers ::=
   * 
   * SET OF DigestAlgorithmIdentifier *)
  (* TODO *)
  let signed_data = int


  let contentinfo =
    let default oid = Asn.(S.parse_error "Unknown contentType %a" OID.pp oid) in
    let f =
      let data = function
        | Some (`C1 x) -> `Data x
        | _ -> parse_error "ContentInfo: expected Data"
      in
      let encrypted = function
        | Some (`C2 x) -> `EncryptedData x
        | _ -> parse_error "ContentInfo: expected EncryptedData"
      in
      let signed = function
        | Some (`C3 x) -> `SignedData x
        | _ -> parse_error "ContentInfo: expected SignedData"
      in
      case_of_oid_f ~default [
        Registry.PKCS7.data, data;
        Registry.PKCS7.encryptedData, encrypted;
        Registry.PKCS7.signedData, signed;
      ]
    in
    let g =
      function
      | `Data x -> Registry.PKCS7.data, Some (`C1 x)
      | `EncryptedData x -> Registry.PKCS7.encryptedData, Some (`C2 x)
      | `SignedData x -> Registry.PKCS7.signedData, Some (`C3 x)
    in
    map f g @@
    sequence2
      (required ~label:"contentType" oid)
      (optional ~label:"content" @@ explicit 0 @@
       choice3 octet_string encrypted_data int)
end
