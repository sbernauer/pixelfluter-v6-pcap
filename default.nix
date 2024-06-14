{ nixpkgs ? import <nixpkgs> {} }:

nixpkgs.mkShell {
  buildInputs = [
    nixpkgs.pkg-config
    nixpkgs.libpcap
  ];
}
