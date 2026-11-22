{
  description = "jj-musubi: Keep jj repos in sync across your machines, live";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
    in
    {
      # Builds against the consumer's nixpkgs.
      overlays.default = final: _prev: {
        jj-musubi = final.callPackage ./package.nix {
          rev = self.shortRev or self.dirtyShortRev or null;
          lastModifiedDate = self.lastModifiedDate or null;
        };
      };

      packages = forAllSystems (system: rec {
        jj-musubi = (nixpkgs.legacyPackages.${system}.extend self.overlays.default).jj-musubi;
        default = jj-musubi;
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              rustc
              clippy
              rustfmt
              pkg-config
            ];
            buildInputs = [ pkgs.zstd ];
            env.ZSTD_SYS_USE_PKG_CONFIG = "1";
          };
        }
      );
    };
}
