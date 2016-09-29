#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "x509" @@ fun _c ->
  Ok [
    Pkg.mllib ~api:["X509"] "lib/x509.mllib";
    Pkg.test "tests/unittestrunner"
  ]
