
include X509_extension_types
open X509_certificate

let cert_usage { asn = cert ; _ } =
  match Asn_grammars.extn_key_usage cert with
  | Some (_, `Key_usage usages) -> Some usages
  | _                           -> None

let supports_usage ?(not_present = false) c u =
  match cert_usage c with
  | Some x -> List.mem u x
  | None   -> not_present

let cert_extended_usage { asn = cert ; _ } =
  match Asn_grammars.extn_ext_key_usage cert with
  | Some (_, `Ext_key_usage usages) -> Some usages
  | _                               -> None

let supports_extended_usage ?(not_present = false) c u =
  match cert_extended_usage c with
  | Some x -> List.mem u x
  | None   -> not_present

let unsupported { asn ; _ } oid = Asn_grammars.extn_unknown asn oid

let subject_alt_names { asn = cert ; _ } =
  match Asn_grammars.extn_subject_alt_name cert with
  | Some (_, `Subject_alt_name names) -> names
  | _ -> []
