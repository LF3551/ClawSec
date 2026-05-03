# Homebrew formula for ClawSec
class Clawsec < Formula
  desc "Modern netcat with AES-256-GCM encryption"
  homepage "https://github.com/LF3551/ClawSec"
  url "https://github.com/LF3551/ClawSec/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "BSD-3-Clause"

  depends_on "openssl@3"

  def install
    cd "unix" do
      system "make", "macos", "CC=#{ENV.cc}", "CXX=#{ENV.cxx}"
      bin.install "clawsec"
    end
  end

  test do
    system "#{bin}/clawsec", "-h"
  end
end
