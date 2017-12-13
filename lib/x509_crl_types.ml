
type revoked_cert = {
  serial : Z.t ;
  date : Ptime.t ;
  extensions : (bool * X509_extension_types.t) list
}
