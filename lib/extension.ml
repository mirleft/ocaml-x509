
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

type authority_key_id = Cstruct.t option * General_name.t * Z.t option

type priv_key_usage_period = [
  | `Interval   of Ptime.t * Ptime.t
  | `Not_after  of Ptime.t
  | `Not_before of Ptime.t
]

type name_constraint = (General_name.b * int * int option) list

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
  [ `Full of General_name.t
  | `Relative of Distinguished_name.t ]

type distribution_point =
  distribution_point_name option *
  reason list option *
  General_name.t option

type 'a extension = bool * 'a

type _ k =
  | Unsupported : Asn.oid -> Cstruct.t extension k
  | Subject_alt_name : General_name.t extension k
  | Authority_key_id : authority_key_id extension k
  | Subject_key_id : Cstruct.t extension k
  | Issuer_alt_name : General_name.t extension k
  | Key_usage : key_usage list extension k
  | Ext_key_usage : extended_key_usage list extension k
  | Basic_constraints : (bool * int option) extension k
  | CRL_number : int extension k
  | Delta_CRL_indicator : int extension k
  | Priv_key_period : priv_key_usage_period extension k
  | Name_constraints : (name_constraint * name_constraint) extension k
  | CRL_distribution_points : distribution_point list extension k
  | Issuing_distribution_point : (distribution_point_name option * bool * bool * reason list option * bool * bool) extension k
  | Freshest_CRL : distribution_point list extension k
  | Reason : reason extension k
  | Invalidity_date : Ptime.t extension k
  | Certificate_issuer : General_name.t extension k
  | Policies : policy list extension k

let pp_one : type a. a k -> Format.formatter -> a -> unit = fun k ppf v ->
  let c_to_str b = if b then "critical " else "" in
  match k, v with
  | Subject_alt_name, (crit, _alt) ->
    Fmt.pf ppf "%ssubjectAlternativeName" (c_to_str crit)
  | Authority_key_id, (crit, _kid) ->
    Fmt.pf ppf "%sauthorityKeyIdentifier" (c_to_str crit)
  | Subject_key_id, (crit, _kid) ->
    Fmt.pf ppf "%ssubjectKeyIdentifier" (c_to_str crit)
  | Issuer_alt_name, (crit, _alt) ->
    Fmt.pf ppf "%sissuerAlternativeNames" (c_to_str crit)
  | Key_usage, (crit, _ku) ->
    Fmt.pf ppf "%skeyUsage" (c_to_str crit)
  | Ext_key_usage, (crit, _eku) ->
    Fmt.pf ppf "%sextendedKeyUsage" (c_to_str crit)
  | Basic_constraints, (crit, _bc) ->
    Fmt.pf ppf "%sbasicConstraints" (c_to_str crit)
  | CRL_number, (crit, _i) ->
    Fmt.pf ppf "%scRLNumber" (c_to_str crit)
  | Delta_CRL_indicator, (crit, _indicator) ->
    Fmt.pf ppf "%sdeltaCRLIndicator" (c_to_str crit)
  | Priv_key_period, (crit, _) ->
    Fmt.pf ppf "%sprivateKeyUsagePeriod" (c_to_str crit)
  | Name_constraints, (crit, _) ->
    Fmt.pf ppf "%snameConstraints" (c_to_str crit)
  | CRL_distribution_points, (crit, _) ->
    Fmt.pf ppf "%scRLDistributionPoints" (c_to_str crit)
  | Issuing_distribution_point, (crit, _) ->
    Fmt.pf ppf "%sissuingDistributionPoint" (c_to_str crit)
  | Freshest_CRL, (crit, _) ->
    Fmt.pf ppf "%sfreshestCRL" (c_to_str crit)
  | Reason, (crit, _) ->
    Fmt.pf ppf "%sreason" (c_to_str crit)
  | Invalidity_date, (crit, _) ->
    Fmt.pf ppf "%sinvalidityDate" (c_to_str crit)
  | Certificate_issuer, (crit, _) ->
    Fmt.pf ppf "%scertificateIssuers" (c_to_str crit)
  | Policies, (crit, _) ->
    Fmt.pf ppf "%spolicies" (c_to_str crit)
  | Unsupported oid, (crit, cs) ->
    Fmt.pf ppf "%sunsupported %a: %a" (c_to_str crit) Asn.OID.pp oid
      Cstruct.hexdump_pp cs

module ID = Registry.Cert_extn

let to_oid : type a. a k -> Asn.oid = function
  | Unsupported oid -> oid
  | Subject_alt_name -> ID.subject_alternative_name
  | Authority_key_id -> ID.authority_key_identifier
  | Subject_key_id -> ID.subject_key_identifier
  | Issuer_alt_name -> ID.issuer_alternative_name
  | Key_usage -> ID.key_usage
  | Ext_key_usage -> ID.extended_key_usage
  | Basic_constraints -> ID.basic_constraints
  | CRL_number -> ID.crl_number
  | Delta_CRL_indicator -> ID.delta_crl_indicator
  | Priv_key_period -> ID.private_key_usage_period
  | Name_constraints -> ID.name_constraints
  | CRL_distribution_points -> ID.crl_distribution_points
  | Issuing_distribution_point -> ID.issuing_distribution_point
  | Freshest_CRL -> ID.freshest_crl
  | Reason -> ID.reason_code
  | Invalidity_date -> ID.invalidity_date
  | Certificate_issuer -> ID.certificate_issuer
  | Policies -> ID.certificate_policies_2

let critical : type a. a k -> a -> bool = fun k v ->
  match k, v with
  | Unsupported _, (b, _) -> b
  | Subject_alt_name, (b, _) -> b
  | Authority_key_id, (b, _) -> b
  | Subject_key_id, (b, _) -> b
  | Issuer_alt_name, (b, _) -> b
  | Key_usage, (b, _) -> b
  | Ext_key_usage, (b, _) -> b
  | Basic_constraints, (b, _) -> b
  | CRL_number, (b, _) -> b
  | Delta_CRL_indicator, (b, _) -> b
  | Priv_key_period, (b, _) -> b
  | Name_constraints, (b, _) -> b
  | CRL_distribution_points, (b, _) -> b
  | Issuing_distribution_point, (b, _) -> b
  | Freshest_CRL, (b, _) -> b
  | Reason, (b, _) -> b
  | Invalidity_date, (b, _) -> b
  | Certificate_issuer, (b, _) -> b
  | Policies, (b, _) -> b

module K = struct
  type 'a t = 'a k

  let compare : type a b. a t -> b t -> (a, b) Gmap.Order.t = fun t t' ->
    let open Gmap.Order in
    match t, t' with
    | Subject_alt_name, Subject_alt_name -> Eq
    | Authority_key_id, Authority_key_id -> Eq
    | Subject_key_id, Subject_key_id -> Eq
    | Issuer_alt_name, Issuer_alt_name -> Eq
    | Key_usage, Key_usage -> Eq
    | Ext_key_usage, Ext_key_usage -> Eq
    | Basic_constraints, Basic_constraints -> Eq
    | CRL_number, CRL_number -> Eq
    | Delta_CRL_indicator, Delta_CRL_indicator -> Eq
    | Priv_key_period, Priv_key_period -> Eq
    | Name_constraints, Name_constraints -> Eq
    | CRL_distribution_points, CRL_distribution_points -> Eq
    | Issuing_distribution_point, Issuing_distribution_point -> Eq
    | Freshest_CRL, Freshest_CRL -> Eq
    | Reason, Reason -> Eq
    | Invalidity_date, Invalidity_date -> Eq
    | Certificate_issuer, Certificate_issuer -> Eq
    | Policies, Policies -> Eq
    | Unsupported oid, Unsupported oid' when Asn.OID.equal oid oid' -> Eq
    | a, b ->
      let r = Asn.OID.compare (to_oid a) (to_oid b) in
      if r = 0 then assert false else if r < 0 then Lt else Gt
end

include Gmap.Make(K)

let pp ppf m = iter (fun (B (k, v)) -> pp_one k ppf v ; Fmt.sp ppf ()) m

module Asn = struct
  open Asn.S
  open Asn_grammars

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
    map (fun (a, b, c) -> (a, def  General_name.empty b, c))
        (fun (a, b, c) -> (a, def' General_name.empty b, c))
    @@
    sequence3
      (optional ~label:"keyIdentifier"  @@ implicit 0 octet_string)
      (optional ~label:"authCertIssuer" @@ implicit 1 General_name.Asn.gen_names)
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
        (required ~label:"base"       General_name.Asn.general_name)
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
      (implicit 0 General_name.Asn.gen_names)
      (implicit 1 Distinguished_name.Asn.name)

  let distribution_point =
    sequence3
      (optional ~label:"distributionPoint" @@ explicit 0 distribution_point_name)
      (optional ~label:"reasons"           @@ implicit 1 reason)
      (optional ~label:"cRLIssuer"         @@ implicit 2 General_name.Asn.gen_names)

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

  let gen_names_of_cs, gen_names_to_cs       = project_exn General_name.Asn.gen_names
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

  let reparse_extension_exn crit = case_of_oid_f [
      (ID.subject_alternative_name,
       fun cs -> B (Subject_alt_name, (crit, gen_names_of_cs cs))) ;
      (ID.issuer_alternative_name,
       fun cs -> B (Issuer_alt_name, (crit, gen_names_of_cs cs))) ;
      (ID.authority_key_identifier,
       fun cs -> B (Authority_key_id, (crit, auth_key_id_of_cs cs))) ;
      (ID.subject_key_identifier,
       fun cs -> B (Subject_key_id, (crit, subj_key_id_of_cs cs))) ;
      (ID.key_usage,
       fun cs -> B (Key_usage, (crit, key_usage_of_cs cs))) ;
      (ID.basic_constraints,
       fun cs -> B (Basic_constraints, (crit, basic_constr_of_cs cs))) ;
      (ID.crl_number,
       fun cs -> B (CRL_number, (crit, int_of_cs cs))) ;
      (ID.delta_crl_indicator,
       fun cs -> B (Delta_CRL_indicator, (crit, int_of_cs cs))) ;
      (ID.extended_key_usage,
       fun cs -> B (Ext_key_usage, (crit, e_key_usage_of_cs cs))) ;
      (ID.private_key_usage_period,
       fun cs -> B (Priv_key_period, (crit, pr_key_peri_of_cs cs))) ;
      (ID.name_constraints,
       fun cs -> B (Name_constraints, (crit, name_con_of_cs cs))) ;
      (ID.crl_distribution_points,
       fun cs -> B (CRL_distribution_points, (crit, crl_distrib_of_cs cs))) ;
      (ID.issuing_distribution_point,
       fun cs -> B (Issuing_distribution_point, (crit, issuing_dp_of_cs cs))) ;
      (ID.freshest_crl,
       fun cs -> B (Freshest_CRL, (crit, crl_distrib_of_cs cs))) ;
      (ID.reason_code,
       fun cs -> B (Reason, (crit, crl_reason_of_cs cs))) ;
      (ID.invalidity_date,
       fun cs -> B (Invalidity_date, (crit, time_of_cs cs))) ;
      (ID.certificate_issuer,
       fun cs -> B (Certificate_issuer, (crit, gen_names_of_cs cs))) ;
      (ID.certificate_policies_2,
       fun cs -> B (Policies, (crit, cert_pol_of_cs cs)))
    ]
      ~default:(fun oid -> fun cs -> B (Unsupported oid, (crit, cs)))

  let unparse_extension (B (k, v)) =
    let v' = match k, v with
      | Subject_alt_name, (_, x) -> gen_names_to_cs x
      | Issuer_alt_name, (_, x) -> gen_names_to_cs x
      | Authority_key_id, (_, x) -> auth_key_id_to_cs x
      | Subject_key_id, (_, x) -> subj_key_id_to_cs  x
      | Key_usage, (_, x) -> key_usage_to_cs x
      | Basic_constraints, (_, x) -> basic_constr_to_cs x
      | CRL_number, (_, x) -> int_to_cs x
      | Delta_CRL_indicator, (_, x) -> int_to_cs x
      | Ext_key_usage, (_, x) -> e_key_usage_to_cs x
      | Priv_key_period, (_, x) -> pr_key_peri_to_cs x
      | Name_constraints, (_, x) -> name_con_to_cs x
      | CRL_distribution_points, (_, x) -> crl_distrib_to_cs x
      | Issuing_distribution_point, (_, x) -> issuing_dp_to_cs x
      | Freshest_CRL, (_, x) -> crl_distrib_to_cs x
      | Reason, (_, x) -> crl_reason_to_cs x
      | Invalidity_date, (_, x) -> time_to_cs x
      | Certificate_issuer, (_, x) -> gen_names_to_cs x
      | Policies, (_, x) -> cert_pol_to_cs x
      | Unsupported _, (_, x) -> x
    in
    to_oid k, critical k v, v'

  let extensions_der =
    let extension =
      let f (oid, crit, cs) =
        reparse_extension_exn (def false crit) (oid, cs)
      and g b =
        let oid, crit, cs = unparse_extension b in
        (oid, def' false crit, cs)
      in
      map f g @@
      sequence3
        (required ~label:"id"       oid)
        (optional ~label:"critical" bool) (* default false *)
        (required ~label:"value"    octet_string)
    in
    let f exts =
      List.fold_left (fun map (B (k, v)) ->
          match add_unless_bound k v map with
          | None -> parse_error "%a already bound" (pp_one k) v
          | Some b -> b)
        empty exts
    and g map = bindings map
    in
    map f g @@ sequence_of extension
end
