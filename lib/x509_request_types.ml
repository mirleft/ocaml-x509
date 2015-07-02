
type request_extensions = [
  | `Password of string
  | `Name of string
  | `Extensions of (bool * X509_extension_types.t) list
]

type request_info = {
  subject : X509_types.distinguished_name ;
  public_key : X509_types.public_key ;
  extensions : request_extensions list ;
}
