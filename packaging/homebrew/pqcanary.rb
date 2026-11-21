class Pqcanary < Formula
  desc "Universal Post-Quantum Cryptographic Security Scanner & CBOM Generator"
  homepage "https://pqcanary.iqumnov.com"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Iqumnov/PQCanary/releases/download/v0.1.0/pqcanary-v0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "SKIP"
    else
      url "https://github.com/Iqumnov/PQCanary/releases/download/v0.1.0/pqcanary-v0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "SKIP"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Iqumnov/PQCanary/releases/download/v0.1.0/pqcanary-v0.1.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "SKIP"
    else
      url "https://github.com/Iqumnov/PQCanary/releases/download/v0.1.0/pqcanary-v0.1.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "SKIP"
    end
  end

  def install
    bin.install "pqcanary"
    bin.install "pqcanary-mcp" if File.exist?("pqcanary-mcp")
  end

  test do
    system "#{bin}/pqcanary", "--version"
  end
end

