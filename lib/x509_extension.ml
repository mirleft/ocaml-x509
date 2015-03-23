
include X509_extension_types
open X509_certificate

let cert_usage { asn = cert ; _ } =
  match Asn_grammars.extn_key_usage cert with
  | Some (_, `Key_usage usages) -> Some usages
  | _                           -> None

let supports_usage ?(not_present = false) c u =
  match cert_usage (get c) with
  | Some x -> List.mem u x
  | None   -> not_present

let cert_extended_usage { asn = cert ; _ } =
  match Asn_grammars.extn_ext_key_usage cert with
  | Some (_, `Ext_key_usage usages) -> Some usages
  | _                               -> None

let supports_extended_usage ?(not_present = false) c u =
  match cert_extended_usage (get c) with
  | Some x -> List.mem u x
  | None   -> not_present
