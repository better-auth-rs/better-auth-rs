{ pkgs, ... }:

{
  packages = [ pkgs.bun pkgs.nodejs pkgs.pnpm pkgs.pkg-config pkgs.openssl pkgs.python3 pkgs.icu78 ];

  env.RUST_ICU_MAJOR_VERSION_NUMBER = "78";
  env.RUST_ICU_LINK_SEARCH_DIR = "${pkgs.icu78}/lib";

  languages.rust = {
    enable = true;
    channel = "stable";
  };

  scripts.check.exec = "./scripts/check.sh";

  enterTest = "check";
}
