{
  description = "FIDO2/U2F software token with CTAP2 support, protected by a TPM";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.buildGoModule {
            pname = "linux-id";
            version = "0-unstable-2026-04-14";

            src = self;

            vendorHash = "sha256-HwLcsjzaFqc0aQrTCoSUdes6ZlnsNZJCdtjwucFyOQ4=";

            ldflags = [
              "-s"
              "-w"
            ];

            meta = {
              description = "FIDO2/U2F token with CTAP2 support, protected by a TPM";
              homepage = "https://github.com/jemilsson/linux-id";
              license = pkgs.lib.licenses.mit;
              mainProgram = "linux-id";
            };
          };
        }
      );

      nixosModules.default = import ./nix/module.nix self;

      overlays.default = final: prev: {
        linux-id = self.packages.${final.system}.default;
      };
    };
}
