
type revoked_cert = {
  serial : Z.t ;
  date : Asn.Time.t ;
  extensions : (bool * X509_extension_types.t) list
}
