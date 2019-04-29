
type key_usage = [
  | `Digital_signature
  | `Content_commitment
  | `Key_encipherment
  | `Data_encipherment
  | `Key_agreement
  | `Key_cert_sign
  | `CRL_sign
  | `Encipher_only
  | `Decipher_only
]

type extended_key_usage = [
  | `Any
  | `Server_auth
  | `Client_auth
  | `Code_signing
  | `Email_protection
  | `Ipsec_end
  | `Ipsec_tunnel
  | `Ipsec_user
  | `Time_stamping
  | `Ocsp_signing
  | `Other of Asn.oid
]

type general_name = [
  | `Other         of (Asn.oid * string)
  | `Rfc_822       of string
  | `DNS           of string
  | `X400_address  of unit
  | `Directory     of Distinguished_name.t
  | `EDI_party     of (string option * string)
  | `URI           of string
  | `IP            of Cstruct.t
  | `Registered_id of Asn.oid
]

type authority_key_id = Cstruct.t option * general_name list * Z.t option

type priv_key_usage_period = [
  | `Interval   of Ptime.t * Ptime.t
  | `Not_after  of Ptime.t
  | `Not_before of Ptime.t
]

type name_constraint = (general_name * int * int option) list

type policy = [ `Any | `Something of Asn.oid ]

type reason = [
  | `Unspecified
  | `Key_compromise
  | `CA_compromise
  | `Affiliation_changed
  | `Superseded
  | `Cessation_of_operation
  | `Certificate_hold
  | `Remove_from_CRL
  | `Privilege_withdrawn
  | `AA_compromise
]

type distribution_point_name =
  [ `Full of general_name list
  | `Relative of Distinguished_name.t ]

type distribution_point =
  distribution_point_name option *
  reason list option *
  Distinguished_name.t option

type t = [
  | `Unsupported       of Asn.oid * Cstruct.t
  | `Subject_alt_name  of general_name list
  | `Authority_key_id  of authority_key_id
  | `Subject_key_id    of Cstruct.t
  | `Issuer_alt_name   of general_name list
  | `Key_usage         of key_usage list
  | `Ext_key_usage     of extended_key_usage list
  | `Basic_constraints of (bool * int option)
  | `CRL_number        of int
  | `Delta_CRL_indicator of int
  | `Priv_key_period   of priv_key_usage_period
  | `Name_constraints  of name_constraint * name_constraint
  | `CRL_distribution_points of distribution_point list
  | `Issuing_distribution_point of distribution_point_name option * bool * bool * reason list option * bool * bool
  | `Freshest_CRL      of distribution_point list
  | `Reason            of reason
  | `Invalidity_date   of Ptime.t
  | `Certificate_issuer of general_name list
  | `Policies          of policy list
]

module Asn = struct
  open Asn.S
  open Asn_grammars

  module General_name = struct
    (* GeneralName is also pretty pervasive. *)

    (* OID x ANY. Hunt down the alternatives.... *)
    (* XXX
     * Cross-check. NSS seems to accept *all* oids here and just assumes UTF8.
     * *)
    let another_name =
      let open Registry in
      let f = function
        | (oid, `C1 n) -> (oid, n)
        | (oid, `C2 n) -> (oid, n)
        | (oid, `C3 _) -> (oid, "")
      and g = function
        | (oid, "") -> (oid, `C3 ())
        | (oid, n ) when Name_extn.is_utf8_id oid -> (oid, `C1 n)
        | (oid, n ) -> (oid, `C2 n) in
      map f g @@
      sequence2
        (required ~label:"type-id" oid)
        (required ~label:"value" @@
         explicit 0
           (choice3 utf8_string ia5_string null))

    and or_address = null (* Horrible crap, need to fill it. *)

    let edi_party_name =
      sequence2
        (optional ~label:"nameAssigner" @@ implicit 0 Distinguished_name.Asn.directory_name)
        (required ~label:"partyName"    @@ implicit 1 Distinguished_name.Asn.directory_name)

    let general_name =
      let f = function
        | `C1 (`C1 x) -> `Other         x
        | `C1 (`C2 x) -> `Rfc_822       x
        | `C1 (`C3 x) -> `DNS           x
        | `C1 (`C4 x) -> `X400_address  x
        | `C1 (`C5 x) -> `Directory     x
        | `C1 (`C6 x) -> `EDI_party     x
        | `C2 (`C1 x) -> `URI           x
        | `C2 (`C2 x) -> `IP            x
        | `C2 (`C3 x) -> `Registered_id x
      and g = function
        | `Other         x -> `C1 (`C1 x)
        | `Rfc_822       x -> `C1 (`C2 x)
        | `DNS           x -> `C1 (`C3 x)
        | `X400_address  x -> `C1 (`C4 x)
        | `Directory     x -> `C1 (`C5 x)
        | `EDI_party     x -> `C1 (`C6 x)
        | `URI           x -> `C2 (`C1 x)
        | `IP            x -> `C2 (`C2 x)
        | `Registered_id x -> `C2 (`C3 x)
      in
      map f g @@
      choice2
        (choice6
           (implicit 0 another_name)
           (implicit 1 ia5_string)
           (implicit 2 ia5_string)
           (implicit 3 or_address)
           (* Everybody uses this as explicit, contrary to x509 (?) *)
           (explicit 4 Distinguished_name.Asn.name)
           (implicit 5 edi_party_name))
        (choice3
           (implicit 6 ia5_string)
           (implicit 7 octet_string)
           (implicit 8 oid))

    let gen_names = sequence_of general_name
  end

  let display_text =
    map (function `C1 s -> s | `C2 s -> s | `C3 s -> s | `C4 s -> s)
      (fun s -> `C4 s)
    @@
    choice4 ia5_string visible_string bmp_string utf8_string

  module ID = Registry.Cert_extn

  let key_usage : key_usage list Asn.t = bit_string_flags [
      0, `Digital_signature
    ; 1, `Content_commitment
    ; 2, `Key_encipherment
    ; 3, `Data_encipherment
    ; 4, `Key_agreement
    ; 5, `Key_cert_sign
    ; 6, `CRL_sign
    ; 7, `Encipher_only
    ; 8, `Decipher_only
    ]

  let ext_key_usage =
    let open ID.Extended_usage in
    let f = case_of_oid [
      (any              , `Any             ) ;
      (server_auth      , `Server_auth     ) ;
      (client_auth      , `Client_auth     ) ;
      (code_signing     , `Code_signing    ) ;
      (email_protection , `Email_protection) ;
      (ipsec_end_system , `Ipsec_end       ) ;
      (ipsec_tunnel     , `Ipsec_tunnel    ) ;
      (ipsec_user       , `Ipsec_user      ) ;
      (time_stamping    , `Time_stamping   ) ;
      (ocsp_signing     , `Ocsp_signing    ) ]
      ~default:(fun oid -> `Other oid)
    and g = function
      | `Any              -> any
      | `Server_auth      -> server_auth
      | `Client_auth      -> client_auth
      | `Code_signing     -> code_signing
      | `Email_protection -> email_protection
      | `Ipsec_end        -> ipsec_end_system
      | `Ipsec_tunnel     -> ipsec_tunnel
      | `Ipsec_user       -> ipsec_user
      | `Time_stamping    -> time_stamping
      | `Ocsp_signing     -> ocsp_signing
      | `Other oid        -> oid
    in
    map (List.map f) (List.map g) @@ sequence_of oid

  let basic_constraints =
    map (fun (a, b) -> (def  false a, b))
        (fun (a, b) -> (def' false a, b))
    @@
    sequence2
      (optional ~label:"cA"      bool)
      (optional ~label:"pathLen" int)

  let authority_key_id =
    map (fun (a, b, c) -> (a, def  [] b, c))
        (fun (a, b, c) -> (a, def' [] b, c))
    @@
    sequence3
      (optional ~label:"keyIdentifier"  @@ implicit 0 octet_string)
      (optional ~label:"authCertIssuer" @@ implicit 1 General_name.gen_names)
      (optional ~label:"authCertSN"     @@ implicit 2 integer)

  let priv_key_usage_period =
    let f = function
      | (Some t1, Some t2) -> `Interval (t1, t2)
      | (Some t1, None   ) -> `Not_before t1
      | (None   , Some t2) -> `Not_after  t2
      | _                  -> parse_error "empty PrivateKeyUsagePeriod"
    and g = function
      | `Interval (t1, t2) -> (Some t1, Some t2)
      | `Not_before t1     -> (Some t1, None   )
      | `Not_after  t2     -> (None   , Some t2) in
    map f g @@
    sequence2
      (optional ~label:"notBefore" @@ implicit 0 generalized_time)
      (optional ~label:"notAfter"  @@ implicit 1 generalized_time)

  let name_constraints =
    let subtree =
      map (fun (base, min, max) -> (base, def  0 min, max))
          (fun (base, min, max) -> (base, def' 0 min, max))
      @@
      sequence3
        (required ~label:"base"       General_name.general_name)
        (optional ~label:"minimum" @@ implicit 0 int)
        (optional ~label:"maximum" @@ implicit 1 int)
    in
    map (fun (a, b) -> (def  [] a, def  [] b))
        (fun (a, b) -> (def' [] a, def' [] b))
    @@
    sequence2
      (optional ~label:"permittedSubtrees" @@ implicit 0 (sequence_of subtree))
      (optional ~label:"excludedSubtrees"  @@ implicit 1 (sequence_of subtree))

  let cert_policies =
    let open ID.Cert_policy in
    let qualifier_info =
      map (function | (oid, `C1 s) when oid = cps     -> s
                    | (oid, `C2 s) when oid = unotice -> s
                    | _ -> parse_error "bad policy qualifier")
        (function s -> (cps, `C1 s))
      @@
      sequence2
        (required ~label:"qualifierId" oid)
        (required ~label:"qualifier"
           (choice2
              ia5_string
            @@
            map (function (_, Some s) -> s | _ -> "#(BLAH BLAH)")
              (fun s -> (None, Some s))
              (sequence2
                 (optional ~label:"noticeRef"
                    (sequence2
                       (required ~label:"organization" display_text)
                       (required ~label:"numbers"      (sequence_of integer))))
                 (optional ~label:"explicitText" display_text))))
    in
    (* "Optional qualifiers, which MAY be present, are not expected to change
     * the definition of the policy."
     * Hence, we just drop them.  *)
    sequence_of @@
    map (function | (oid, _) when oid = any_policy -> `Any
                  | (oid, _)                       -> `Something oid)
      (function | `Any           -> (any_policy, None)
                | `Something oid -> (oid, None))
    @@
    sequence2
      (required ~label:"policyIdentifier" oid)
      (optional ~label:"policyQualifiers" (sequence_of qualifier_info))

  let reason : reason list Asn.t = bit_string_flags [
      0, `Unspecified
    ; 1, `Key_compromise
    ; 2, `CA_compromise
    ; 3, `Affiliation_changed
    ; 4, `Superseded
    ; 5, `Cessation_of_operation
    ; 6, `Certificate_hold
    ; 7, `Privilege_withdrawn
    ; 8, `AA_compromise
    ]

  let distribution_point_name =
    map (function | `C1 s -> `Full s | `C2 s -> `Relative s)
      (function | `Full s -> `C1 s | `Relative s -> `C2 s)
    @@
    choice2
      (implicit 0 General_name.gen_names)
      (implicit 1 Distinguished_name.Asn.name)

  let distribution_point =
    sequence3
      (optional ~label:"distributionPoint" @@ explicit 0 distribution_point_name)
      (optional ~label:"reasons"           @@ implicit 1 reason)
      (optional ~label:"cRLIssuer"         @@ implicit 2 Distinguished_name.Asn.name)

  let crl_distribution_points = sequence_of distribution_point

  let issuing_distribution_point =
    map (fun (a, b, c, d, e, f) -> (a, def  false b, def  false c, d, def  false e, def  false f))
        (fun (a, b, c, d, e, f) -> (a, def' false b, def' false c, d, def' false e, def' false f))
    @@
    sequence6
      (optional ~label:"distributionPoint"          @@ explicit 0 distribution_point_name)
      (optional ~label:"onlyContainsUserCerts"      @@ implicit 1 bool)
      (optional ~label:"onlyContainsCACerts"        @@ implicit 2 bool)
      (optional ~label:"onlySomeReasons"            @@ implicit 3 reason)
      (optional ~label:"indirectCRL"                @@ implicit 4 bool)
      (optional ~label:"onlyContainsAttributeCerts" @@ implicit 5 bool)

  let crl_reason : reason Asn.t =
    let alist = [
        0, `Unspecified
      ; 1, `Key_compromise
      ; 2, `CA_compromise
      ; 3, `Affiliation_changed
      ; 4, `Superseded
      ; 5, `Cessation_of_operation
      ; 6, `Certificate_hold
      ; 8, `Remove_from_CRL
      ; 9, `Privilege_withdrawn
      ; 10, `AA_compromise
      ]
    in
    let rev = List.map (fun (k, v) -> (v, k)) alist in
    enumerated (fun i -> List.assoc i alist) (fun k -> List.assoc k rev)

  let gen_names_of_cs, gen_names_to_cs       = project_exn General_name.gen_names
  and auth_key_id_of_cs, auth_key_id_to_cs   = project_exn authority_key_id
  and subj_key_id_of_cs, subj_key_id_to_cs   = project_exn octet_string
  and key_usage_of_cs, key_usage_to_cs       = project_exn key_usage
  and e_key_usage_of_cs, e_key_usage_to_cs   = project_exn ext_key_usage
  and basic_constr_of_cs, basic_constr_to_cs = project_exn basic_constraints
  and pr_key_peri_of_cs, pr_key_peri_to_cs   = project_exn priv_key_usage_period
  and name_con_of_cs, name_con_to_cs         = project_exn name_constraints
  and crl_distrib_of_cs, crl_distrib_to_cs   = project_exn crl_distribution_points
  and cert_pol_of_cs, cert_pol_to_cs         = project_exn cert_policies
  and int_of_cs, int_to_cs                   = project_exn int
  and issuing_dp_of_cs, issuing_dp_to_cs     = project_exn issuing_distribution_point
  and crl_reason_of_cs, crl_reason_to_cs     = project_exn crl_reason
  and time_of_cs, time_to_cs                 = project_exn generalized_time

  (* XXX 4.2.1.4. - cert policies! ( and other x509 extensions ) *)

  let reparse_extension_exn = case_of_oid_f [
    (ID.subject_alternative_name, fun cs ->
      `Subject_alt_name (gen_names_of_cs cs)) ;

    (ID.issuer_alternative_name, fun cs ->
      `Issuer_alt_name (gen_names_of_cs cs)) ;

    (ID.authority_key_identifier, fun cs ->
      `Authority_key_id (auth_key_id_of_cs cs)) ;

    (ID.subject_key_identifier, fun cs ->
      `Subject_key_id (subj_key_id_of_cs cs)) ;

    (ID.key_usage, fun cs ->
      `Key_usage (key_usage_of_cs cs)) ;

    (ID.basic_constraints, fun cs ->
      `Basic_constraints (basic_constr_of_cs cs));

    (ID.crl_number, fun cs ->
      `CRL_number (int_of_cs cs));

    (ID.delta_crl_indicator, fun cs ->
      `Delta_CRL_indicator (int_of_cs cs));

    (ID.extended_key_usage, fun cs ->
      `Ext_key_usage (e_key_usage_of_cs cs)) ;

    (ID.private_key_usage_period, fun cs ->
      `Priv_key_period (pr_key_peri_of_cs cs)) ;

    (ID.name_constraints, fun cs ->
      `Name_constraints (name_con_of_cs cs)) ;

    (ID.crl_distribution_points, fun cs ->
      `CRL_distribution_points (crl_distrib_of_cs cs)) ;

    (ID.issuing_distribution_point, fun cs ->
      `Issuing_distribution_point (issuing_dp_of_cs cs)) ;

    (ID.freshest_crl, fun cs ->
      `Freshest_CRL (crl_distrib_of_cs cs)) ;

    (ID.reason_code, fun cs ->
      `Reason (crl_reason_of_cs cs)) ;

    (ID.invalidity_date, fun cs ->
      `Invalidity_date (time_of_cs cs)) ;

    (ID.certificate_issuer, fun cs ->
      `Certificate_issuer (gen_names_of_cs cs)) ;

    (ID.certificate_policies_2, fun cs ->
      `Policies (cert_pol_of_cs cs))
    ]
    ~default:(fun oid cs -> `Unsupported (oid, cs))

  let unparse_extension = function
    | `Subject_alt_name  x -> (ID.subject_alternative_name, gen_names_to_cs    x)
    | `Issuer_alt_name   x -> (ID.issuer_alternative_name , gen_names_to_cs    x)
    | `Authority_key_id  x -> (ID.authority_key_identifier, auth_key_id_to_cs  x)
    | `Subject_key_id    x -> (ID.subject_key_identifier  , subj_key_id_to_cs  x)
    | `Key_usage         x -> (ID.key_usage               , key_usage_to_cs    x)
    | `Basic_constraints x -> (ID.basic_constraints       , basic_constr_to_cs x)
    | `CRL_number        x -> (ID.crl_number              , int_to_cs          x)
    | `Delta_CRL_indicator x -> (ID.delta_crl_indicator   , int_to_cs          x)
    | `Ext_key_usage     x -> (ID.extended_key_usage      , e_key_usage_to_cs  x)
    | `Priv_key_period   x -> (ID.private_key_usage_period, pr_key_peri_to_cs  x)
    | `Name_constraints  x -> (ID.name_constraints        , name_con_to_cs     x)
    | `CRL_distribution_points x -> (ID.crl_distribution_points, crl_distrib_to_cs x)
    | `Issuing_distribution_point x -> (ID.issuing_distribution_point, issuing_dp_to_cs x)
    | `Freshest_CRL      x -> (ID.freshest_crl            , crl_distrib_to_cs  x)
    | `Reason            x -> (ID.reason_code             , crl_reason_to_cs   x)
    | `Invalidity_date   x -> (ID.invalidity_date         , time_to_cs         x)
    | `Certificate_issuer x -> (ID.certificate_issuer     , gen_names_to_cs    x)
    | `Policies          x -> (ID.certificate_policies_2  , cert_pol_to_cs     x)
    | `Unsupported (oid, cs) -> (oid, cs)

  let extensions_der =
    let extension =
      let f (oid, b, cs) =
        (def false b, reparse_extension_exn (oid, cs))
      and g (b, ext) =
        let (oid, cs) = unparse_extension ext in (oid, def' false b, cs)
      in
      map f g @@
      sequence3
        (required ~label:"id"       oid)
        (optional ~label:"critical" bool) (* default false *)
        (required ~label:"value"    octet_string)
    in
    sequence_of extension
end
