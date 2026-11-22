# Adapted from https://github.com/bos/jj-musubi/pull/169 (romen), with nixpkgs'
# buildRustPackage instead of crane, so the flake needs no input but nixpkgs.
{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  zstd,
  aws-lc,
  installShellFiles,
  rev ? null,
  lastModifiedDate ? null,
}:

rustPlatform.buildRustPackage {
  pname = "jj-musubi";
  version = (lib.importTOML ./Cargo.toml).workspace.package.version;

  # Only what the build reads, so docs and Nix edits leave the source unchanged.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./crates
    ];
  };

  cargoLock.lockFile = ./Cargo.lock;
  cargoBuildFlags = [
    "--package"
    "jj-musubi"
  ];

  # The tests drive real git and jj repositories and spawn daemons.
  doCheck = false;

  nativeBuildInputs = [
    pkg-config
    installShellFiles
  ];
  # nixpkgs' Rust hook sets AWS_LC_SYS_USE_SYSTEM, for tailscale-rs's TLS.
  buildInputs = [
    zstd
    aws-lc
  ];

  env = {
    ZSTD_SYS_USE_PKG_CONFIG = "1";
    # Nix strips the binary; without this the build needs gigabytes more disk.
    CARGO_PROFILE_RELEASE_DEBUG = "false";
  }
  # Semver build metadata, so a daemon sees a later build from source as newer.
  // lib.optionalAttrs (rev != null && lastModifiedDate != null) {
    MUSUBI_BUILD = "${lastModifiedDate}.${rev}";
  };

  postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    installShellCompletion --cmd musubi \
      --bash <(COMPLETE=bash $out/bin/musubi) \
      --zsh <(COMPLETE=zsh $out/bin/musubi) \
      --fish <(COMPLETE=fish $out/bin/musubi)
  '';

  meta = {
    description = "Keep jj repos in sync across your machines, live";
    homepage = "https://github.com/m-sp/jj-musubi";
    license = lib.licenses.asl20;
    mainProgram = "musubi";
  };
}
