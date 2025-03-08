{
  description = "Python project with Nix, venv and pip";

  inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"; };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

    in {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs;
          [
            (python311.withPackages (ps:
              with ps; [
                boto3
                pytest
                pytest-cov
                isort
                black
                flake8
                mypy
              ]))
          ];
      };
    };
}
