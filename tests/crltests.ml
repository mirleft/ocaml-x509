open OUnit2

open X509

let with_loaded_files file ~f =
  let pre = "./crl/" in
  let fullpath1 = pre ^ file ^ ".pem"
  and fullpath2 = pre ^ file ^ ".crl"
  in
  let fd1 = Unix.(openfile fullpath1 [O_RDONLY] 0)
  and fd2 = Unix.(openfile fullpath2 [O_RDONLY] 0)
  in
  let buf1 = Unix_cstruct.of_fd fd1
  and buf2 = Unix_cstruct.of_fd fd2
  in
  try let r = f buf1 buf2 in Unix.close fd1 ; Unix.close fd2 ; r
  with e -> Unix.close fd1 ; Unix.close fd2 ; raise e

let one f _ =
  with_loaded_files f ~f:(fun cert crl ->
      let cert = Encoding.Pem.Certificate.of_pem_cstruct1 cert in
      let pubkey = X509.public_key cert in
      match Encoding.crl_of_cstruct crl with
      | None -> assert_failure "failed to parse crl"
      | Some crl when CRL.validate crl pubkey -> ()
      | Some _ -> assert_failure "couldn't verify cert")

let crl_tests = [
  "CRL 1 is good" >:: one "1" ;
  "CRL 2 is good" >:: one "2" ;
  "CRL 3 is good" >:: one "3" ;
  "CRL 4 is good" >:: one "4" ;
  "CRL 5 is good" >:: one "5" ;
  "CRL 6 is good" >:: one "6" ;
  "CRL 7 is good" >:: one "7" ;
  "CRL 8 is good" >:: one "8" ;
  "CRL 9 is good" >:: one "9" ;
  "CRL 10 is good" >:: one "10" ;
  "CRL 11 is good" >:: one "11" ;
  "CRL 12 is good" >:: one "12" ;
  "CRL 13 is good" >:: one "13" ;
  "CRL 14 is good" >:: one "14" ;
  "CRL 15 is good" >:: one "15" ;
  "CRL 16 is good" >:: one "16" ;
  "CRL 17 is good" >:: one "17" ;
  "CRL 18 is good" >:: one "18" ;
  "CRL 19 is good" >:: one "19" ;
  "CRL 20 is good" >:: one "20" ;
  "CRL 21 is good" >:: one "21" ;
]
