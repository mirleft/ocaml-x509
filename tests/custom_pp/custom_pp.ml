let fido_u2f_transport_oid =
  Asn.OID.(base 1 3 <| 6 <| 1 <| 4 <| 1 <| 45724 <| 2 <| 1 <| 1)

let fido_u2f_transport_oid_name = "id-fido-u2f-ce-transports"

type transport = [
  | `Bluetooth_classic
  | `Bluetooth_low_energy
  | `Usb
  | `Nfc
  | `Usb_internal
]

let pp_transport ppf = function
  | `Bluetooth_classic -> Fmt.string ppf "BluetoothClassic"
  | `Bluetooth_low_energy -> Fmt.string ppf "BluetoothLowEnergy"
  | `Usb -> Fmt.string ppf "USB"
  | `Nfc -> Fmt.string ppf "NFC"
  | `Usb_internal -> Fmt.string ppf "USBInternal"

let transports =
  let opts = [
    (0, `Bluetooth_classic);
    (1, `Bluetooth_low_energy);
    (2, `Usb);
    (3, `Nfc);
    (4, `Usb_internal);
  ] in
  Asn.S.bit_string_flags opts

let decode_transports cs =
  match Asn.decode (Asn.codec Asn.der transports) cs with
  | Ok (a, cs) ->
    if String.length cs = 0 then Ok a else Error (`Msg "trailing bytes")
  | Error (`Parse msg) -> Error (`Msg msg)

let custom_pp ppf (oid, data) =
  if Asn.OID.equal oid fido_u2f_transport_oid then
    match decode_transports data with
    | Error `Msg _e ->
      Fmt.pf ppf "%s invalid-data" fido_u2f_transport_oid_name
    | Ok transports ->
      Fmt.pf ppf "%s %a" fido_u2f_transport_oid_name Fmt.(list ~sep:(any ",") pp_transport) transports
  else
    Fmt.pf ppf "unsupported %a: %a" Asn.OID.pp oid (Ohex.pp_hexdump ()) data

let () =
  let fullpath = "../testcertificates/fido.pem" in
  let fd = open_in fullpath in
  let ln = in_channel_length fd in
  let buf = Bytes.create ln in
  really_input fd buf 0 ln;
  close_in_noerr fd;
  let buf = Bytes.unsafe_to_string buf in
  match X509.Certificate.decode_pem buf with
  | Error `Msg e -> failwith e
  | Ok cert ->
    Format.printf "Certificate: %a\n" (X509.Certificate.pp' custom_pp) cert
