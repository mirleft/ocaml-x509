(* https://tools.ietf.org/html/rfc6960 *)

let version_v1 = 0

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

module Asn_common = struct
  (* open Asn_grammars *)
  open Asn.S

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
end



module Request = struct
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

    let request =
      let f (reqCert, singleRequestExtensions) =
        {reqCert; singleRequestExtensions}
      in
      let g {reqCert; singleRequestExtensions} =
        (reqCert, singleRequestExtensions)
      in
      map f g @@
      sequence2
        (required ~label:"reqCert" Asn_common.cert_id)
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


module Response = struct

   (* OCSPResponseStatus ::= ENUMERATED {
    *     successful            (0),  -- Response has valid confirmations
    *     malformedRequest      (1),  -- Illegal confirmation request
    *     internalError         (2),  -- Internal error in issuer
    *     tryLater              (3),  -- Try again later
    *                                 -- (4) is not used
    *     sigRequired           (5),  -- Must sign the request
    *     unauthorized          (6)   -- Request unauthorized
    * } *)
  type status = [
    | `Successful
    | `MalformedRequest
    | `InternalError
    | `TryLater
    | `SigRequired
    | `Unauthorized
  ]

  let status_to_int = function
    | `Successful -> 0
    | `MalformedRequest -> 1
    | `InternalError -> 2
    | `TryLater -> 3
    | `SigRequired -> 5
    | `Unauthorized -> 6

  let status_of_int = function
    |  0 -> `Successful
    |  1 -> `MalformedRequest
    |  2 -> `InternalError
    |  3 -> `TryLater
    |  5 -> `SigRequired
    |  6 -> `Unauthorized
    | x -> Asn.S.parse_error "Unknown status %d" x


  let pp_status ppf = function
    | `Successful -> Fmt.string ppf "Successful"
    | `MalformedRequest -> Fmt.string ppf "MalformedRequest"
    | `InternalError -> Fmt.string ppf "InternalError"
    | `TryLater -> Fmt.string ppf "TryLater"
    | `SigRequired -> Fmt.string ppf "SigRequired"
    | `Unauthorized -> Fmt.string ppf "Unauthorized"

   (* ResponseBytes ::=       SEQUENCE {
    *     responseType   OBJECT IDENTIFIER,
    *     response       OCTET STRING } *)

  (* OCSPResponse ::= SEQUENCE {
   *     responseStatus         OCSPResponseStatus,
   *     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL } *)

  type t = {
    responseStatus: status;
    responseBytes: (Asn.oid * Cstruct.t) option;
  }

  let pp ppf {responseStatus;responseBytes;} =
    Fmt.pf ppf "OCSPResponse @[<1>{@ responseStatus=%a;@ responseBytes=%a@ }@]"
      pp_status responseStatus
      (Fmt.option ~none:(Fmt.any "None") @@
       Fmt.pair ~sep:Fmt.comma Asn.OID.pp Cstruct.hexdump_pp)
      responseBytes

  (* RevokedInfo ::= SEQUENCE {
   *   revocationTime              GeneralizedTime,
   *   revocationReason    [0]     EXPLICIT CRLReason OPTIONAL } *)
  type revoked_info = {
    revocationTime: Ptime.t;
    revocationReason: Extension.reason option;
  }

  let pp_revoked_info ppf {revocationTime;revocationReason;} =
    Fmt.pf ppf "RevokedInfo @[<1>{@ revocationTime=%a;@ revocationReason=%a;@ }@]"
      Ptime.pp revocationTime
      (Fmt.option ~none:(Fmt.any "None") @@ Extension.pp_reason)
      revocationReason

   (* CertStatus ::= CHOICE {
    *     good        [0]     IMPLICIT NULL,
    *     revoked     [1]     IMPLICIT RevokedInfo,
    *     unknown     [2]     IMPLICIT UnknownInfo } *)

  type cert_status = [
    | `Good
    | `Revoked of revoked_info
    | `Unknown
  ]

  let pp_cert_status ppf = function
    | `Good -> Fmt.pf ppf "Good"
    | `Revoked info -> Fmt.pf ppf "Revoked of %a" pp_revoked_info info
    | `Unknown -> Fmt.pf ppf "Unknown"

   (* SingleResponse ::= SEQUENCE {
    *  certID                       CertID,
    *  certStatus                   CertStatus,
    *  thisUpdate                   GeneralizedTime,
    *  nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
    *  singleExtensions   [1]       EXPLICIT Extensions OPTIONAL } *)

  type single_response = {
    certID: cert_id;
    certStatus: cert_status;
    thisUpdate: Ptime.t;
    nextUpdate: Ptime.t option;
    singleExtensions: Extension.t option;
  }

  let pp_single_response ppf {certID;certStatus;thisUpdate;nextUpdate;singleExtensions;} =
    Fmt.pf ppf "SingleResponse @[<1>{@ certID=%a;@ certStatus=%a;@ thisUpdate=%a;@ nextUpdate=%a;@ singleExtensions=%a;@ }@]"
      pp_cert_id certID
      pp_cert_status certStatus
      Ptime.pp thisUpdate
      (Fmt.option ~none:(Fmt.any "None") @@ Ptime.pp) nextUpdate
      (Fmt.option ~none:(Fmt.any "None") @@ Extension.pp) singleExtensions

 
 (* ResponderID ::= CHOICE {
  *    byName               [1] Name,
  *    byKey                [2] KeyHash }
  *   KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
   (excluding the tag and length fields)
  *)
  type responder_id = [
    | `ByName of Distinguished_name.t
    | `ByKey of Cstruct.t
  ]

  let pp_responder_id ppf = function
    | `ByName dn -> Fmt.pf ppf "ByName %a" Distinguished_name.pp dn
    | `ByKey hash -> Fmt.pf ppf "ByKey %a" Cstruct.hexdump_pp hash

  (* ResponseData ::= SEQUENCE {
   *  version              [0] EXPLICIT Version DEFAULT v1,
   *  responderID              ResponderID,
   *  producedAt               GeneralizedTime,
   *  responses                SEQUENCE OF SingleResponse,
   *  responseExtensions   [1] EXPLICIT Extensions OPTIONAL } *)
  type response_data = {
    version: int;
    responderID: responder_id;
    producedAt: Ptime.t;
    responses: single_response list;
    responseExtensions: Extension.t option;
  }

  let pp_response_data ppf {version;responderID;producedAt;responses;responseExtensions;} =
    Fmt.pf ppf "ResponseData @[<1>{@ version=%d;@ responderID=%a;@ producedAt=%a;@ responses=%a;@ responseExtensions=%a@ }@]"
      version
      pp_responder_id responderID
      Ptime.pp producedAt
      (Fmt.list ~sep:Fmt.semi @@ pp_single_response) responses
      (Fmt.option ~none:(Fmt.any "None") @@ Extension.pp) responseExtensions
  
   (* BasicOCSPResponse       ::= SEQUENCE {
    *    tbsResponseData      ResponseData,
    *    signatureAlgorithm   AlgorithmIdentifier,
    *    signature            BIT STRING,
    *    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL } *)
  type basic_ocsp_response = {
    tbsResponseData: response_data;
    signatureAlgorithm: Algorithm.t;
    signature: Cstruct.t;
    certs: Certificate.t list option;
  }

  let pp_basic_ocsp_response ppf {tbsResponseData;signatureAlgorithm;signature;certs;} =
    Fmt.pf ppf "BasicOCSPResponse @[<1>{@ tbsResponseData=%a;@ signatureAlgorithm=%a;@ signature=%a;@ certs=%a@ }@]"
      pp_response_data tbsResponseData
      Algorithm.pp signatureAlgorithm
      Cstruct.hexdump_pp signature
      (Fmt.option ~none:(Fmt.any "None") @@
       Fmt.list ~sep:Fmt.semi @@ Certificate.pp) certs


  module Asn = struct
    open Asn_grammars
    open Asn.S
      (* open Registry *)

    let status : status Asn.t =
      enumerated status_of_int status_to_int

    let ocsp_response =
      let f (responseStatus,responseBytes) =
        {responseStatus;responseBytes}
      in
      let g {responseStatus;responseBytes} =
        (responseStatus,responseBytes)
      in
      map f g @@
      sequence2
        (required ~label:"responseStatus" status)
        (optional ~label:"responseBytes" @@ explicit 0 @@
         sequence2
           (required ~label:"responseType" oid)
           (required ~label:"response" octet_string))

    let ocsp_response_of_cs, ocsp_response_to_cs =
      projections_of Asn.der ocsp_response

    let revoked_info =
      let f (revocationTime,revocationReason) =
        {revocationTime;revocationReason}
      in
      let g {revocationTime;revocationReason} =
        (revocationTime,revocationReason)
      in
      map f g @@
      sequence2
        (required ~label:"revocationTime" generalized_time_no_frac_s)
        (optional ~label:"revocationReason" @@ explicit 0 @@ Extension.Asn.reason_enumerated)

    let cert_status : cert_status Asn.t =
      let f = function
        | `C1 () -> `Good
        | `C2 ri -> `Revoked ri
        | `C3 () -> `Unknown
      in
      let g = function
        | `Good -> `C1 ()
        | `Revoked ri -> `C2 ri
        | `Unknown -> `C3 ()
      in
      map f g @@
      choice3
        (implicit 0 @@ null)
        (implicit 1 @@ revoked_info)
        (implicit 2 @@ null)

    let single_response =
      let f (certID,certStatus,thisUpdate,nextUpdate,singleExtensions) =
        {certID;certStatus;thisUpdate;nextUpdate;singleExtensions;}
      in
      let g {certID;certStatus;thisUpdate;nextUpdate;singleExtensions;} =
        (certID,certStatus,thisUpdate,nextUpdate,singleExtensions)
      in
      map f g @@
      sequence5
        (required ~label:"certID" @@ Asn_common.cert_id)
        (required ~label:"certStatus" @@ cert_status)
        (required ~label:"thisUpdate" @@ generalized_time_no_frac_s)
        (optional ~label:"nextUpdate" @@ explicit 0 @@ generalized_time_no_frac_s)
        (optional ~label:"singleExtensions" @@ explicit 1 @@
         Extension.Asn.extensions_der)

    let responder_id : responder_id Asn.t =
      let f = function
        | `C1 dn -> `ByName dn
        | `C2 hash -> `ByKey hash
      in
      let g = function
        | `ByName dn -> `C1 dn
        | `ByKey hash -> `C2 hash
      in
      map f g @@
      choice2 Distinguished_name.Asn.name octet_string

    let response_data =
      let f (version,responderID,producedAt,responses,responseExtensions) =
        let version = match version with
          | Some v -> v
          | None -> version_v1
        in
        {version;responderID;producedAt;responses;responseExtensions;}
      in
      let g {version;responderID;producedAt;responses;responseExtensions;} =
        let version = Some version in
        (version,responderID,producedAt,responses,responseExtensions)
      in
      map f g @@
      sequence5
        (optional ~label:"version" @@ explicit 0 @@ int)
        (required ~label:"responderID" responder_id)
        (required ~label:"producedAt" generalized_time_no_frac_s)
        (required ~label:"responses" @@ sequence_of single_response)
        (optional ~label:"responseExtensions" @@ explicit 1 @@
         Extension.Asn.extensions_der)

    let response_data_of_cs,response_data_to_cs =
      projections_of Asn.der response_data

    let basic_ocsp_response =
      let f (tbsResponseData,signatureAlgorithm,signature,certs) =
        let certs = match certs with
          | None -> None
          | Some certs ->
            let encode cert =
              let raw = Certificate.Asn.certificate_to_cstruct cert in
              Certificate.{raw; asn=cert}
            in
            Some (List.map encode certs)
        in
        {tbsResponseData;signatureAlgorithm;signature;certs}
      in
      let g {tbsResponseData;signatureAlgorithm;signature;certs} =
        let certs = match certs with
          | None -> None
          | Some certs ->
            Some (List.map (fun Certificate.{asn;_} -> asn) certs)
        in
        (tbsResponseData,signatureAlgorithm,signature,certs)
      in
      map f g @@
      sequence4
        (required ~label:"tbsResponseData" response_data)
        (required ~label:"signatureAlgorithm" Algorithm.identifier)
        (required ~label:"signature" bit_string_cs)
        (optional ~label:"certs" @@ sequence_of Certificate.Asn.certificate)

    let basic_ocsp_response_of_cs,basic_ocsp_response_to_cs =
      projections_of Asn.der basic_ocsp_response

  end

  let make_basic_ocsp_response ?(digest=`SHA256) ?certs ~private_key tbsResponseData =
    let signatureAlgorithm = Algorithm.of_signature_algorithm
        (Private_key.keytype private_key)
        digest
    in
    let response_data_der = Asn.response_data_to_cs tbsResponseData in
    let signature = match private_key with
      | `RSA priv ->
        Mirage_crypto_pk.Rsa.PKCS1.sign ~hash:digest ~key:priv
          (`Message response_data_der)
    in
    {tbsResponseData;signatureAlgorithm;signature;certs;}

  let make_ocsp_response_success basic_ocsp_response =
    let oid = Registry.Cert_extn.Private_internet_extensions.ad_ocsp_basic in
    let response = Asn.basic_ocsp_response_to_cs basic_ocsp_response in
    {responseStatus=`Successful;
     responseBytes=Some (oid, response);}

end
