(* pkcs12 https://tools.ietf.org/html/rfc7292
 * pkcs7 https://tools.ietf.org/html/rfc2315
 * pkcs8 https://tools.ietf.org/html/rfc5208
 * pkcs9 https://tools.ietf.org/html/rfc2985
 * x.509 https://tools.ietf.org/html/rfc5280
 * https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf *)

let src = Logs.Src.create "x509.pkcs12" ~doc:"X509 pkcs12"
module Log = (val Logs.src_log src : Logs.LOG)

module Attribute = struct
  open Asn.S
  open Asn_grammars

  (* PKCS12Attribute ::= SEQUENCE {
   *     attrId      ATTRIBUTE.&id ({PKCS12AttrSet}),
   *     attrValues  SET OF ATTRIBUTE.&Type ({PKCS12AttrSet}{@attrId})
   * } -- This type is compatible with the X.500 type 'Attribute'
   * 
   * PKCS12AttrSet ATTRIBUTE ::= {
   *     friendlyName |
   *     localKeyId,
   *     ... -- Other attributes are allowed
   * } *)

   (* friendlyName ATTRIBUTE ::= {
    *         WITH SYNTAX BMPString (SIZE(1..pkcs-9-ub-friendlyName))
    *         EQUALITY MATCHING RULE caseIgnoreMatch
    *         SINGLE VALUE TRUE
    *         ID pkcs-9-at-friendlyName
    * }
    * 
    * localKeyId ATTRIBUTE ::= {
    *         WITH SYNTAX OCTET STRING
    *         EQUALITY MATCHING RULE octetStringMatch
    *         SINGLE VALUE TRUE
    *         ID pkcs-9-at-localKeyId
    * } *)
  type t =
    | FriendlyName of string
    | LocalKeyId of Cstruct.t

  let attribute =
    let default oid = Asn.(S.parse_error "Unknown attrId %a" OID.pp oid) in
    let f =
      let friendlyname = function
        | `C1 hd::[] -> FriendlyName hd
        | _ -> parse_error "Attribute friendlyName must be single"
      in
      let localkeyid = function
        | `C2 hd::[] -> LocalKeyId hd
        | _ -> parse_error "Attribute localKeyId must be single"
      in
      case_of_oid_f ~default [
        Registry.PKCS9.friendly_name, friendlyname;
        Registry.PKCS9.local_key_id, localkeyid;
      ]
    in
    let g = function
      | FriendlyName x ->
        Registry.PKCS9.friendly_name, [`C1 x]
      | LocalKeyId x ->
        Registry.PKCS9.local_key_id, [`C2 x]
    in
    map f g @@
    sequence2
      (required ~label:"attrId" oid)
      (required ~label:"attrValues" @@
       set_of (choice2 bmp_string octet_string))
end

module SafeBag = struct
  open Asn.S
  open Asn_grammars

  (* type cert_type =
   *   | X509 of Cstruct.t (\* TODO *\)
   *   | SDSI of string (\* TODO *\)
   * 
   * let cert_bag =
   *   let default oid = Asn.(S.parse_error "Unknown certId %a" OID.pp oid) in
   *   let f =
   *     let x509 = function
   *       | `C1 x -> X509 x
   *       | _ -> parse_error "CertBag: expected x509Certificate"
   *     in
   *     let sdsi = function
   *       | `C2 x -> SDSI x
   *       | _ -> parse_error "CertBag: expected sdsiCertificate"
   *     in
   *     case_of_oid_f ~default [
   *       Registry.PKCS12.x509_certificate, x509;
   *       Registry.PKCS12.sdsi_certificate, sdsi;
   *     ]
   *   in
   *   let g =
   *     function
   *     | X509 x -> Registry.PKCS12.x509_certificate, `C1 x
   *     | SDSI x -> Registry.PKCS12.sdsi_certificate, `C2 x
   *   in
   *   map f g @@
   *   sequence2
   *     (required ~label:"certId" oid)
   *     (required ~label:"certValue" @@ explicit 0 @@
   *        choice2 octet_string ia5_string) *)

  type bag =
    | KeyBag of Mirage_crypto_pk.Rsa.priv
    (* | PKCS8ShroudedKeyBag of Cstruct.t (\* TODO *\) *)
    | CertBag of Certificate.t

  type t = bag * Attribute.t list

  (* TODO:
   *  -- KeyBag
   *  KeyBag ::= PrivateKeyInfo
   *  -- Shrouded KeyBag
   *  PKCS8ShroudedKeyBag ::= EncryptedPrivateKeyInfo
   *  -- CertBag
   *  CertBag ::= SEQUENCE {
   *      certId    BAG-TYPE.&id   ({CertTypes}),
   *      certValue [0] EXPLICIT BAG-TYPE.&Type ({CertTypes}{@certId})
   *  }
   *  x509Certificate BAG-TYPE ::=
   *      {OCTET STRING IDENTIFIED BY {certTypes 1}}
   *      -- DER-encoded X.509 certificate stored in OCTET STRING
   *  sdsiCertificate BAG-TYPE ::=
   *      {IA5String IDENTIFIED BY {certTypes 2}}
   *      -- Base64-encoded SDSI certificate stored in IA5String
   *  CertTypes BAG-TYPE ::= {
   *      x509Certificate |
   *      sdsiCertificate,
   *      ... -- For future extensions
   *  }
   *  -- CRLBag
   *  -- Secret Bag *)

  (* since asn1 does not yet support ANY defined BY, we develop a rather
     complex grammar covering all supported bags
     we are interning all types of bags into safebag structure
     Thanks to @hannesm
  *)
  let safebag : t Asn.t =
    (* let decode_cert, encode_cert = project_exn Certificate.Asn.certificate in *)
    let encode_cert = Certificate.encode_der in
    let decode_cert = fst (project_exn Certificate.Asn.certificate) in
    let decode_cert cs =
      let asn = decode_cert cs in
      Certificate.{asn; raw = cs}
    in
    let f (oid, (a, algo, data)) =
      match a, algo, data with
      (* PrivateKeyInfo *)
      | `C1 version, Some privateKeyAlgorithm, `C1 privateKey
        when Asn.OID.equal oid Registry.PKCS12.keyBag ->
        let key = Private_key.Asn.reparse_private ~sloppy:false
            (version, privateKeyAlgorithm, privateKey) in
        KeyBag key
      (* CertBag *)
      | `C2 certId, None, `C2 certValue
        when Asn.OID.equal oid Registry.PKCS12.certBag ->
        if Asn.OID.equal certId Registry.PKCS12.x509_certificate then
          let cert = decode_cert certValue in
          CertBag cert
        else
          parse_error "CertBag: only X509Certificate is supported"
        (* TODO: CRLBag *)
        (* else if Asn.OID.equal oid PKCS12.crl_bag && Asn.OID.equal id crl_oid then
         *   match Crl.decode_der data with
         *   | Error e -> error e
         *   | Ok crl -> `Crl crl, attrs
         * else
         *   parse_error "crl bag with non-standard crl" *)
      (* | `C3 algo, None, `C1 data when Asn.OID.equal oid PKCS12.pkcs8_shrouded_key_bag ->
       *   `Encrypted_private_key (algo, data), attrs *)
      | _ -> Asn.(S.parse_error "Unknown bagId %a" OID.pp oid)
    in
    let f (oid, value, attrs) =
      let bag = f (oid, value) in
      let attrs = match attrs with
        | None -> []
        | Some x -> x
      in
      bag, attrs
    in
    let g (bag, attrs) =
      let attrs = Some attrs in
      let oid, d = match bag with
        | KeyBag pk ->
          let v, algo, data = Private_key.Asn.unparse_private pk in
          (* Pretending PrivateKeyInfo *)
          Registry.PKCS12.keyBag, (
            `C1 v, (* version *)
            Some algo, (* privateKeyAlgorithm *)
            `C1 data (* privateKey *)
          )
        (* | PKCS8ShroudedKeyBag k ->
         *   Registry.PKCS12.pkcs8ShroudedKeyBag, `C2 k *)
        | CertBag cert ->
          let cert_der = encode_cert cert in
          (* Pretending CertBag *)
          Registry.PKCS12.certBag, (
            `C2 Registry.PKCS12.x509_certificate, (* certId *)
            None, (* not used *)
            `C2 cert_der (* certValue *)
          )
      in
      (oid, d, attrs)
    in
    map f g @@
    sequence3
      (required ~label:"bagId" oid)
      (required ~label:"bagValue" @@
       (* explicit 0 @@  choice2 pk encrypted_privatekey_info) *)
       (explicit 0
          (sequence3
             (required ~label:"fst" (choice3 int oid Algorithm.identifier))
             (optional ~label:"algorithm" Algorithm.identifier)
             (required ~label:"data" (choice2 octet_string (explicit 0 octet_string))))))
      (* (explicit 0 (* encrypted private key *)
         (sequence2
            (required ~label:"encryption algorithm" Algorithm.identifier)
            (required ~label:"encrypted data" octet_string))) *)
      (* (explicit 0 (* private key ] *)
            (sequence3
              (required ~label:"version"             int)
              (required ~label:"privateKeyAlgorithm" Algorithm.identifier)
              (required ~label:"privateKey"          octet_string)))  *)
      (* (explicit 0 (* cert / crl *)
            (sequence2
               (required ~label:"oid" oid)
               (required ~label:"data" (explicit 0 octet_string)))) *)
      (optional ~label:"bagAttributes" @@ set_of Attribute.attribute)

end

module MacData = struct
  open Asn.S
  (* open Asn_grammars *)

  type t = {
    algo: Algorithm.t;
    digest: Cstruct.t;
    salt: Cstruct.t;
    iterations: int;
  }

  let make ?(algo=Algorithm.SHA1) ?(iterations=2048) ?salt
      ~password data =
    let salt = match salt with
      | None -> Cstruct.of_string "123456789" (* TODO *)
      | Some x -> x
    in
    (* TODO *)
    let digest = Cstruct.of_string (password ^ data) in
    {algo;digest;salt;iterations;}
    

  let mac_data =
    let f ((algo, digest), salt, iterations) =
      {algo;digest;salt;iterations;}
    in
    let g {algo;digest;salt;iterations;} =
      (algo, digest), salt, iterations
    in
    map f g @@
    sequence3
      (required ~label:"mac" Pkcs7.Asn.digest_info)
      (required ~label:"macSalt" octet_string)
      (required ~label:"iterations" int)
end


module Asn = struct
  open Asn.S
  open Asn_grammars

  type safe_contents = SafeBag.t list
  let safecontents : safe_contents t = sequence_of SafeBag.safebag

  (* -- Data if unencrypted
   * -- EncryptedData if password-encrypted
   * -- EnvelopedData if public key-encrypted *)
  let safecont_contentinfo =
    let encode, decode = project_exn safecontents in
    let f = function
      | `Data x -> encode x
      | `EncryptedData _ -> parse_error "TODO: safecont_contentinfo"
      | `SignedData _ -> parse_error "TODO: safecont_contentinfo"
    in
    let g c =
      (* TODO: encrypted and signed *)
      `Data (decode c)
    in
    map f g @@ Pkcs7.Asn.contentinfo

  type authenticated_safe = safe_contents list
  let authenticated_safe : authenticated_safe t =
    sequence_of safecont_contentinfo


  (* From rfc7292:
   * the contentType field of authSafe shall be of type data
   * or signedData. *)
  let authsafe_contentinfo =
    let encode, decode = project_exn authenticated_safe in
    let f = function
      | `Data x -> encode x
      | `SignedData _ -> parse_error "TODO: authsafe_contentinfo"
      | _ -> parse_error "authSafe must contentType be either data or signedData"
    in
    let g c = `Data (decode c) in
    map f g @@ Pkcs7.Asn.contentinfo

  let pfx =
    let f (_version, auth_content, mac) =
      auth_content, mac
    in
    let g (auth_content, mac) =
      3, auth_content, mac
    in
    map f g @@
    sequence3
      (required ~label:"version" int)
      (required ~label:"authSafe" authsafe_contentinfo)
      (optional ~label:"macData" MacData.mac_data)

end
