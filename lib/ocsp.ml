(* https://tools.ietf.org/html/rfc6960 *)


module Request = struct
  (* 
   CertID          ::=     SEQUENCE {
        hashAlgorithm       AlgorithmIdentifier,
        issuerNameHash      OCTET STRING, -- Hash of issuer's DN
        issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
        serialNumber        CertificateSerialNumber }
  *)
  type cert_id = {
    hashAlgorithm: Algorithm.t;
    issuerNameHash: Cstruct.t;
    issuerKeyHash: Cstruct.t;
    serialNumber: Z.t;
  }

  let pp_cert_id ppf {hashAlgorithm;issuerNameHash;issuerKeyHash;serialNumber} =
    Fmt.pf ppf "CertID @[<1>{@ algo=%a;@ issuerNameHash=%a;@ issuerKeyHash=%a;@ serialNumber=%a@ }@]"
      Algorithm.pp hashAlgorithm
      Cstruct.hexdump_pp issuerNameHash
      Cstruct.hexdump_pp issuerKeyHash
      Z.pp_print serialNumber

  (*
  Request ::= SEQUENCE {
     reqCert                     CertID,
     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
  *)
  type request = {
    reqCert: cert_id;
    singleRequestExtensions: Extension.t option;
  }

  let pp_request ppf {reqCert;singleRequestExtensions;} =
    Fmt.pf ppf "Request @[<1>{@ reqCert=%a;@ singleRequestExtensions=%a;@ }@]"
      pp_cert_id reqCert
      (Fmt.option ~none:(Fmt.any "None") Extension.pp) singleRequestExtensions

  (*
  TBSRequest      ::=     SEQUENCE {
         version             [0]     EXPLICIT Version DEFAULT v1,
         requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
         requestList                 SEQUENCE OF Request,
         requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }

  *)
  type tbs_request = {
    version: int;
    requestorName: General_name.b option;
    requestList: request list;
    requestExtensions: Extension.t option;
  }

  let pp_tbs_request ppf {version;requestorName;requestList;requestExtensions;} =
    let pp_general_name ppf x =
      let open General_name in
      match x with
      | B (k, v) ->
        General_name.pp_k k ppf v
    in
    Fmt.pf ppf "TBSRequest @[<1>{@ version=%d;@ requestorName=%a;@ requestList=[@ %a@ ];@ requestExtensions=%a@ }@]"
      version
      (Fmt.option ~none:(Fmt.any "None") pp_general_name) requestorName
      (Fmt.list ~sep:Fmt.semi pp_request) requestList
      (Fmt.option ~none:(Fmt.any "None") Extension.pp) requestExtensions

  let version_v1 = 0

  (*
  Signature       ::=     SEQUENCE {
         signatureAlgorithm      AlgorithmIdentifier,
         signature               BIT STRING,
         certs               [0] EXPLICIT SEQUENCE OF Certificate
     OPTIONAL}
  *)
  type signature = {
    signatureAlgorithm: Algorithm.t;
    signature: Cstruct.t;
    certs: Certificate.t list option;
  }

  let pp_signature ppf {signatureAlgorithm;signature;certs;} =
    Fmt.pf ppf "Signature @[<1>{@ signatureAlgorithm=%a;@ signature=%a;@ certs=%a}@]"
      Algorithm.pp signatureAlgorithm
      Cstruct.hexdump_pp signature
      (Fmt.option ~none:(Fmt.any "None") @@
       Fmt.brackets @@
       Fmt.list ~sep:Fmt.semi Certificate.pp) certs

  (*
   OCSPRequest     ::=     SEQUENCE {
         tbsRequest                  TBSRequest,
         optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
  *)
  type t = {
    tbsRequest: tbs_request;
    optionalSignature: signature option;
  }

  let pp ppf {tbsRequest;optionalSignature} =
    Fmt.pf ppf "OCSPRequest @[<1>{@ tbsRequest=%a;@ optionalSignature=%a@ }@]"
      pp_tbs_request tbsRequest
      (Fmt.option ~none:(Fmt.any "None") pp_signature) optionalSignature

  module Asn_ = Asn

  module Asn = struct
    open Asn_grammars
    open Asn.S
    (* open Registry *)

    let cert_id =
      let f (hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber) =
        {hashAlgorithm;
         issuerNameHash;
         issuerKeyHash;
         serialNumber;}
      in
      let g {hashAlgorithm;issuerNameHash;issuerKeyHash;serialNumber;} =
        (hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber)
      in
      map f g @@
      sequence4
        (required ~label:"hashAlgorithm" Algorithm.identifier)
        (required ~label:"issuerNameHash" octet_string)
        (required ~label:"issuerKeyHash" octet_string)
        (required ~label:"serialNumber" integer)

    let request =
      let f (reqCert, singleRequestExtensions) =
        {reqCert; singleRequestExtensions}
      in
      let g {reqCert; singleRequestExtensions} =
        (reqCert, singleRequestExtensions)
      in
      map f g @@
      sequence2
        (required ~label:"reqCert" cert_id)
        (optional ~label:"singleRequestExtensions" @@
         explicit 0 Extension.Asn.extensions_der)

    let tbs_request =
      let f (version,requestorName,requestList,requestExtensions) =
        let version = match version with
          | Some v -> v
          | None -> version_v1
        in
        {version;requestorName;requestList;requestExtensions;}
      in
      let g {version;requestorName;requestList;requestExtensions;} =
        let version = Some version in
        (version,requestorName,requestList,requestExtensions)
      in
      map f g @@
      sequence4
        (optional ~label:"version" @@ explicit 0 int)
        (optional ~label:"requestorName" @@
         explicit 1 General_name.Asn.general_name)
        (required ~label:"requestList" @@ sequence_of request)
        (optional ~label:"requestExtensions" @@ Extension.Asn.extensions_der)

    let signature =
      let f (signatureAlgorithm,signature,certs) =
        let certs = match certs with
          | None -> None
          | Some certs ->
            let encode cert =
              let raw = Certificate.Asn.certificate_to_cstruct cert in
              Certificate.{raw; asn=cert}
            in
            Some (List.map encode certs)
        in
        {signatureAlgorithm;signature;certs}
      in
      let g {signatureAlgorithm;signature;certs} =
        let certs = match certs with
          | None -> None
          | Some certs ->
            Some (List.map (fun Certificate.{asn;_} -> asn) certs)
        in
        (signatureAlgorithm,signature,certs)
      in
      map f g @@
      sequence3
        (required ~label:"signatureAlgorithm" Algorithm.identifier)
        (required ~label:"signature" bit_string_cs)
        (optional ~label:"certs" @@ sequence_of Certificate.Asn.certificate)

    let ocsp_request =
      let f (tbsRequest,optionalSignature) =
        {tbsRequest;optionalSignature;}
      in
      let g {tbsRequest;optionalSignature;} =
        (tbsRequest,optionalSignature)
      in
      map f g @@
      sequence2
        (required ~label:"tbsRequest" tbs_request)
        (optional ~label:"optionalSignature" signature)

    let (ocsp_request_of_cstruct, ocsp_request_to_cstruct) =
      projections_of Asn.der ocsp_request

  end

end
