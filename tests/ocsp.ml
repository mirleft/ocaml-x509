open X509

(* 
How files for test1 were generated:
test1.pem:
openssl req -new -key key.pem -nodes -out test1.csr \
    -subj '/CN=test1.example.com/' 
openssl x509 -req -days 3650 -in test1.csr -CA certificate.pem \
    -CAkey key.pem -set_serial 10000 -out test1.pem
openssl x509 -in test1.pem -noout -text

request.der:
openssl ocsp -issuer certificate.pem \
   -cert test1.pem \
   -no_nonce -reqout request.der
openssl ocsp -reqin request.der -text

response.der:
openssl ocsp -index index.txt -rsigner certificate.pem \
   -rkey key.pem -CA certificate.pem \
   -reqin request.der -respout response.der
openssl ocsp -respin response.der -CAfile certificate.pem -text

*)

let cs_mmap file =
  Unix_cstruct.of_fd Unix.(openfile file [O_RDONLY] 0)

let data file = cs_mmap ("./ocsp/" ^ file)

let responder_cert = match Certificate.decode_pem (data "certificate.pem") with
  | Ok c -> c
  | Error _ -> assert false
let responder_dn = Certificate.subject responder_cert
let test1_serial = Z.of_int 0x2710

let z_testable = Alcotest.testable Z.pp_print Z.equal
let cert_dn_testable = Alcotest.testable Distinguished_name.pp Distinguished_name.equal


let test_request () =
  let open OCSP.Request in
  match Asn.ocsp_request_of_cstruct (data "request.der") with
  | Error _ -> Alcotest.fail "could not decode OCSP request"
  | Ok request ->
    (* Fmt.pr "request=%a" pp request; *)
    match request with
    | {tbsRequest={
        requestList=[
          {reqCert={serialNumber;_};_}
        ];_
      };_
      } ->
      Alcotest.(check z_testable __LOC__ test1_serial serialNumber)
    | _ -> Alcotest.fail "something wrong with OCSP request"

let test_response () =
  let open OCSP.Response in
  match Asn.ocsp_response_of_cs (data "response.der") with
  | Error _ -> Alcotest.fail "could not decode OCSP response"
  | Ok response ->
    (* Fmt.pr "response=%a" pp response; *)
    match response with
    | {responseStatus=`Successful;
       responseBytes=Some (_oid, basic_response);} -> begin
        match Asn.basic_ocsp_response_of_cs basic_response with
        | Error _ -> Alcotest.fail "could not decode basic_response"
        | Ok {tbsResponseData={
            responderID=`ByName responder;
            responses=[{
                certStatus=`Good;
                certID={serialNumber;_};_
              }];_
          };_} ->
          Alcotest.(check z_testable __LOC__ test1_serial serialNumber);
          Alcotest.(check cert_dn_testable __LOC__ responder responder_dn)
        | Ok _ -> Alcotest.fail "something wrong with basic_response"
      end
    | _ -> Alcotest.fail "something wrong with OCSP response"

let tests = [
  "OpenSSL request", `Quick, test_request ;
  "OpenSSL response", `Quick, test_response ;
]
