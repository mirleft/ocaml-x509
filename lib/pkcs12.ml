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


module Mac = struct
  (* https://tools.ietf.org/html/rfc7292#appendix-A *)
  (* The following code has been stolen from @hannesm PR *)


  (*  In this specification, however, all passwords are created from
   *  BMPStrings with a NULL terminator.  This means that each character in
   *  the original BMPString is encoded in 2 bytes in big-endian format
   *  (most-significant byte first).  There are no Unicode byte order
   *  marks.  The 2 bytes produced from the last character in the BMPString
   *  are followed by 2 additional bytes with the value 0x00.
   * 
   *  To illustrate with a simple example, if a user enters the 6-character
   *  password "Beavis", the string that PKCS #12 implementations should
   *  treat as the password is the following string of 14 bytes:
   * 
   *  0x00 0x42 0x00 0x65 0x00 0x61 0x00 0x76 0x00 0x69 0x00 0x73 0x00 0x00 *)
  (* TODO: this actually should be unicode ucs2 recoding *)
  let prepare_pw str =
    let l = String.length str in
    let cs = Cstruct.create ((succ l) * 2) in
    for i = 0 to pred l do
      Cstruct.set_char cs (succ (i * 2)) (String.get str i)
    done;
    cs

  (* Construct a string, D (the "diversifier"), by concatenating v/8
   *      copies of ID. *)
  let id len purpose =
    let b = Cstruct.create len in
    let id = match purpose with
      | `Encryption -> 1
      | `Iv -> 2
      | `Hmac -> 3
    in
    Cstruct.memset b id;
    b

  (* Let H be a hash function built around a compression function f:
   * 
   *    Z_2^u x Z_2^v -> Z_2^u
   * 
   * (that is, H has a chaining variable and output of length u bits, and
   * the message input to the compression function of H is v bits).  The
   * values for u and v are as follows:
   * 
   *         HASH FUNCTION     VALUE u        VALUE v
   *           MD2, MD5          128            512
   *             SHA-1           160            512
   *            SHA-224          224            512
   *            SHA-256          256            512
   *            SHA-384          384            1024
   *            SHA-512          512            1024
   *          SHA-512/224        224            1024
   *          SHA-512/256        256            1024 *)
  (* this is the block size, which is not exposed by nocrypto :/ *)
  (* TODO: I'm pretty sure that at least MD5 operates 4 blocks of
     32bit length, so what the *** is [v] ? *)
  let v = function
    | `MD5 | `SHA1 -> 512 / 8
    | `SHA224 | `SHA256 | `SHA384 | `SHA512 -> 1024 / 8

  let fill ~data ~out =
    let len = Cstruct.len out
    and l = Cstruct.len data
    in
    let rec c off =
      if off < len then begin
        Cstruct.blit data 0 out off (min (len - off) l);
        c (off + l)
      end
    in
    c 0

  (* 2.  Concatenate copies of the salt together to create a string S of
   *     length v(ceiling(s/v)) bits (the final copy of the salt may be
   *     truncated to create S).  Note that if the salt is the empty
   *     string, then so is S.
   * 
   * 3.  Concatenate copies of the password together to create a string P
   *     of length v(ceiling(p/v)) bits (the final copy of the password
   *     may be truncated to create P).  Note that if the password is the
   *     empty string, then so is P. *)
  let fill_or_empty size data =
    let l = Cstruct.len data in
    if l = 0 then data
    else
      let len = size * ((l + size - 1) / size) in
      let buf = Cstruct.create len in
      fill ~data ~out:buf;
      buf

  (* Actually, its not pkcs5 pbes, but pkcs12 mac algorithm *)
  let pbes algorithm purpose password salt iterations n =
    let pw = prepare_pw password
    and v = v algorithm
    and u = Mirage_crypto.Hash.digest_size algorithm
    in
    let diversifier = id v purpose in
    let salt = fill_or_empty v salt in
    let pass = fill_or_empty v pw in
    let out = Cstruct.create n in
    let rec one off i =
      let ai = ref (Mirage_crypto.Hash.digest algorithm (Cstruct.append diversifier i)) in
      for _j = 1 to pred iterations do
        ai := Mirage_crypto.Hash.digest algorithm !ai;
      done;
      Cstruct.blit !ai 0 out off (min (n - off) u);
      if u >= n - off then () else
        (* 6B *)
        (* Concatenate copies of Ai to create a string B of length v
         * bits (the final copy of Ai may be truncated to create B). *)
        let b = Cstruct.create v in
        fill ~data:!ai ~out:b;
        (* 6C *)
        (* Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
         * blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
         * setting I_j=(I_j+B+1) mod 2^v for each j. *)
        let i' = Cstruct.create (Cstruct.len i) in
        for j = 0 to pred (Cstruct.len i / v) do
          let c = ref 1 in
          for k = pred v downto 0 do
            let idx = j * v + k in
            c := (!c + Cstruct.get_uint8 i idx + Cstruct.get_uint8 b k) land 0xFFFF;
            Cstruct.set_uint8 i' idx (!c land 0xFF);
            c := !c lsr 8;
          done;
        done;
        one (off + u) i'
    in
    let i = Cstruct.append salt pass in
    one 0 i;
    out

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

  let make ?(algo=`SHA1) ?(iterations=2048) ?salt
      ~password data =
    let salt = match salt with
      | None -> Mirage_crypto_rng.generate 8
      | Some x -> x
    in
    let key = Mac.pbes algo `Hmac password salt iterations
        (Mirage_crypto.Hash.digest_size algo) in
    let digest = Mirage_crypto.Hash.mac `SHA1 ~key data in
    (* let digest = Cstruct.of_string (password ^ data) in *)
    let algo = Algorithm.of_hash algo in
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


module Asn_ = struct
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
    let f = function
      | `Data x -> x
      | `SignedData _ -> parse_error "TODO: authsafe_contentinfo"
      | _ -> parse_error "authSafe must contentType be either data or signedData"
    in
    let g c = `Data c in
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

let pfx ?mac_password safecontents =
  let codec = Asn.codec Asn.ber Asn_.authenticated_safe in
  let authenticatedsafe = Asn.encode codec safecontents in
  let mac = match mac_password with
    | Some password -> Some (MacData.make ~password authenticatedsafe)
    | None -> None
  in
  let codec = Asn.codec Asn.ber Asn_.pfx in
  let pfx_ber = Asn.encode codec (authenticatedsafe, mac) in
  pfx_ber

  
module Asn = Asn_
