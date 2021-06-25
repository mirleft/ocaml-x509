open! Core
open! Async
open! Import

include module type of struct
  include X509.PKCS12
end

val decode_der : contents:string -> t Or_error.t

val verify
  :  string
  -> t
  -> [ `Certificate of X509.Certificate.t
     | `Crl of X509.CRL.t
     | `Decrypted_private_key of X509.Private_key.t
     | `Private_key of X509.Private_key.t
     ]
       list
       Or_error.t
