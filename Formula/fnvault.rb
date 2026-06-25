class Fnvault < Formula
  desc "Touch ID/passphrase-gated credential vault with a CLI, TUI, and daemon"
  homepage "https://github.com/fnLog0/fnVault"
  url "https://github.com/fnLog0/fnVault/archive/refs/tags/v0.1.2.tar.gz"
  sha256 "7147305cd64806797814c02e1951240014703ed8e1b2b5eb60c89898dc59e29d"
  license "MIT"
  head "https://github.com/fnLog0/fnVault.git", branch: "main"

  depends_on "rust" => :build

  def install
    # Build from source: locally compiled binaries are not quarantined, so no
    # Apple notarization is required. Install both `vault` and `vaultd` into the
    # same prefix (the CLI auto-starts the daemon from its own directory).
    system "cargo", "install", *std_cargo_args(path: "crates/vaultd")
    system "cargo", "install", *std_cargo_args(path: "crates/vault")

    generate_completions_from_executable(bin/"vault", "completions")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/vault --version")
    # `skills` is served from the embedded skill data, so it needs no daemon.
    assert_match "fnvault", shell_output("#{bin}/vault skills list")
  end
end
