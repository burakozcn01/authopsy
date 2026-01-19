class Authopsy < Formula
  desc "RBAC vulnerability scanner for REST APIs"
  homepage "https://github.com/burakozcn01/authopsy"
  url "https://github.com/burakozcn01/authopsy/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "65fef461a3bdfb41d8127a58dc227192dc51c1ff4084efc2d7aaa4dfa85a6963"
  license "MIT"
  head "https://github.com/burakozcn01/authopsy.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "authopsy #{version}", shell_output("#{bin}/authopsy --version")
  end
end
