#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let opams =
  let lint_deps_excluding = Some ["ounit"; "oUnit"] in
  [Pkg.opam_file ~lint_deps_excluding "opam"]

let () =
  Pkg.describe ~opams "x509" @@ fun _c ->
  Ok [
    Pkg.mllib ~api:["X509"] "lib/x509.mllib";
    Pkg.test "tests/unittestrunner"
  ]
