# Forces every QEMU hostfwd forwarded port onto loopback, including SSH.
#
# vagrant-qemu 0.6.3's Driver#start hardcodes the SSH forward as
# "hostfwd=tcp::#{ssh_port}-:22" with no host_ip seam at all (driver.rb:129,153), and
# action/start_instance.rb's forwarded_ports() explicitly skips id == "ssh" ("SSH port is
# handled by PrepareForwardedPortCollisionParams") before building the :ports list that
# *does* respect a Vagrantfile's host_ip — so no Vagrantfile-level config can loopback-bind
# the SSH forward. Confirmed directly against the installed gem source, 2026-09-23.
#
# Other forwarded ports (winrm, rdp, ...) DO respect an explicit host_ip in the Vagrantfile,
# via that same :ports list — see the host_ip: "127.0.0.1" redeclarations in
# windows-x64/Vagrantfile. This patch is defense-in-depth for those (belt-and-suspenders
# against a future misconfigured port lacking host_ip) and the *only* fix for SSH.
#
# QEMU's hostfwd syntax is [tcp|udp]:[hostaddr]:hostport-[guestaddr]:guestport; the protocol
# segment is itself optional (defaulting to tcp), so an unqualified forward can read
# "hostfwd=::2222-:22" with no "tcp"/"udp" at all — this patch handles that form the same as
# an explicit one. An empty hostaddr segment binds every interface. This patch rewrites any
# empty-hostaddr hostfwd clause in the constructed QEMU argv to loopback-only, at the point
# Driver#execute actually shells out to qemu-system-*, so it applies regardless of which code
# path built the string.
#
# Loaded unconditionally from every guest Vagrantfile via require_relative, before `vagrant
# up` starts QEMU, so no guest can accidentally expose SSH/WinRM/RDP to the LAN.
#
# This patch reaches into vagrant-qemu's Driver#execute by prepending a module — there is no
# public extension point for this. That makes it silently stop working if a future
# vagrant-qemu release changes Driver#execute's argv shape (e.g. no longer building the
# hostfwd string this way at all) or the hardcoded SSH-forward construction described above.
# Two independent guards against that:
#   1. A version pin checked inside execute() itself, below — refuses to run QEMU at all
#      against any vagrant-qemu other than the one this patch was verified against.
#      Deliberately NOT checked at load time (this file is require_relative'd unconditionally
#      from every guest Vagrantfile, so a load-time check runs on EVERY `vagrant` invocation
#      that touches this Vagrantfile, including `destroy`/`halt` against an already-running
#      QEMU process): reading driver.rb end to end - `stop`
#      (halt) sends QMP commands over the control port or SIGKILLs the process directly, and
#      `delete` (destroy) only removes files - neither ever calls `execute`. A load-time
#      check would mean that after a plugin upgrade to an unpinned vagrant-qemu version, THIS
#      Ruby raise, not just a failed `vagrant up`, is what a developer hits when trying to
#      `destroy`/`halt` a guest QEMU is still running - permanently orphaning it, with no
#      `vagrant` command left able to stop it. Checking inside execute() instead means the
#      pin only ever blocks *starting* a new QEMU process (or an `export`/`package`
#      `qemu-img` call), never stopping/removing an existing one.
#   2. A fail-closed post-rewrite assertion inside execute() itself, so even an in-range
#      version whose behavior somehow doesn't match what's documented above turns into a hard
#      `vagrant up` failure instead of a silent loopback-only guarantee that no longer holds.
PINNED_VAGRANT_QEMU_VERSION = "0.6.3"

module VagrantPlugins
  module QEMU
    class Driver
      module ForceLoopbackHostfwd
        LOOPBACK = "127.0.0.1"
        # Matches a hostfwd clause's host-address segment as actually rewritten above:
        # hostfwd=tcp:127.0.0.1:2222-:22 → captures "127.0.0.1". The protocol segment is
        # optional (see the file-level comment above), so this also matches the protocol-less
        # hostfwd=:127.0.0.1:2222-:22 form. Anything the gsub above didn't touch, or touched
        # incorrectly, shows up here as an empty or "0.0.0.0" capture.
        HOSTFWD_HOSTADDR = /hostfwd=(?:tcp|udp)?:([^:]*):/

        def execute(*cmd, **opts, &block)
          installed_version = Vagrant::Plugin::Manager.instance.installed_plugins.dig("vagrant-qemu", "installed_gem_version")
          if installed_version != PINNED_VAGRANT_QEMU_VERSION
            raise "devvm: fix_qemu_loopback_only.rb is pinned to vagrant-qemu #{PINNED_VAGRANT_QEMU_VERSION}, " \
                  "but #{installed_version.inspect} is installed. This file patches a private method " \
                  "(VagrantPlugins::QEMU::Driver#execute) by name; re-verify the hostfwd rewrite still " \
                  "applies against the new version, then update PINNED_VAGRANT_QEMU_VERSION."
          end

          cmd = cmd.map do |arg|
            if arg.is_a?(String)
              # (tcp|udp)? is optional: also rewrites the protocol-less "hostfwd=::2222-:22"
              # form (empty capture) to "hostfwd=:127.0.0.1:2222-:22", not just the
              # "hostfwd=tcp::"/"hostfwd=udp::" forms.
              arg.gsub(/hostfwd=(tcp|udp)?::/, "hostfwd=\\1:#{LOOPBACK}:")
            else
              arg
            end
          end

          cmd.each do |arg|
            next unless arg.is_a?(String)

            arg.scan(HOSTFWD_HOSTADDR).each do |(hostaddr)|
              # Require exactly LOOPBACK, not just "not obviously wrong" (blank/0.0.0.0):
              # any other concrete address (a LAN IP, "::1", a hostname, ...) is just as
              # much a loopback-only violation and just as silent if let through.
              if hostaddr != LOOPBACK
                raise "devvm: QEMU hostfwd loopback rewrite did not take - found a " \
                      "non-loopback host address in: #{arg.inspect}. This means " \
                      "vagrant-qemu's Driver#execute argv shape no longer matches what this " \
                      "patch expects; refusing to start QEMU rather than silently exposing a " \
                      "forwarded port to the LAN."
              end
            end
          end

          super(*cmd, **opts, &block)
        end
      end

      prepend ForceLoopbackHostfwd
    end
  end
end
