#!/bin/sh

case "$OCAML_VERSION" in
    4.01.0) ppa=avsm/ocaml41+opam12 ;;
    4.02.0) ppa=avsm/ocaml42+opam12 ;;
    *) echo Unknown $OCAML_VERSION; exit 1 ;;
esac

echo "yes" | sudo add-apt-repository ppa:$ppa
sudo apt-get update -qq
sudo apt-get install -qq ocaml ocaml-native-compilers camlp4-extra opam libgmp-dev

export OPAMYES=1

opam init git://github.com/ocaml/opam-repository >/dev/null 2>&1

opam pin -n add nocrypto git://github.com/mirleft/ocaml-nocrypto.git
opam pin -n add asn1-combinators git://github.com/mirleft/ocaml-asn1-combinators.git

opam pin -n add x509 .

opam install --deps-only x509
opam install oUnit

eval `opam config env`
ocaml setup.ml -configure --enable-tests
ocaml setup.ml -build
ocaml setup.ml -test
