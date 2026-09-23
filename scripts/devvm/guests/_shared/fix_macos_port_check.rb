# Works around a host-specific bug where Vagrant misdetects every forwarded port as already
# in use, which makes `vagrant up` fail outright (ForwardPortCollision) or exhaust the entire
# auto-correction range (ForwardPortAutolistEmpty) even when nothing is actually listening.
#
# Root cause, confirmed directly against Vagrant's own bundled Ruby on this machine (Vagrant
# 2.4.9 / Ruby 3.3.8 arm64-darwin):
#
#   Socket.tcp("127.0.0.1", 12345, connect_timeout: 0.5).close
#
# reports success (port "open") even though nothing listens on 12345 and a plain blocking
# `TCPSocket.new("127.0.0.1", 12345)` correctly raises Errno::ECONNREFUSED for the same port at
# the same time. This is exactly the check `Vagrant::Util::IsPortOpen.is_port_open?` — used by
# every provider's forwarded-port collision handler, including vagrant-qemu's, not anything
# guest- or box-specific — performs, so it affects any guest with a forwarded port, not just
# Windows ones. It reproduced deterministically (not a rare flake) on this host on 2026-09-23.
#
# The fix: swap the check for a plain blocking connect with an explicit timeout, which this
# host's Ruby gets right. Loaded from every guest Vagrantfile via `require_relative` so the
# patch is applied before `vagrant up`'s port-collision middleware runs, regardless of guest.
require "socket"
require "timeout"

module Vagrant
  module Util
    module IsPortOpen
      def is_port_open?(host, port)
        # Vagrant core passes "0.0.0.0" (its default for an unset host_ip) to mean "any
        # interface"; a client can't connect *to* 0.0.0.0, so probe loopback instead — the same
        # substitution meaning already used by the code this replaces.
        target = (host.nil? || host.empty? || host == "0.0.0.0") ? "127.0.0.1" : host
        Timeout.timeout(1) { TCPSocket.new(target, port).close }
        true
      rescue Errno::ETIMEDOUT, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH,
             Errno::EACCES, Errno::ENOTCONN, Errno::EALREADY, Timeout::Error
        false
      end
    end
  end
end
