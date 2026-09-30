{ pkgs, ... }:

{
  packages = [ pkgs.bun pkgs.nodejs pkgs.pnpm pkgs.pkg-config pkgs.openssl pkgs.python3 ];

  languages.rust = {
    enable = true;
    channel = "stable";
  };

  scripts.check.exec = "./scripts/check.sh";

  enterTest = "check";
}
