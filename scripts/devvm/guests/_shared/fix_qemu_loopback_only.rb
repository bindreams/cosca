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
# QEMU's hostfwd syntax is [tcp|udp]:[hostaddr]:hostport-[guestaddr]:guestport; an empty
# hostaddr segment binds every interface. This patch rewrites any empty-hostaddr hostfwd
# clause in the constructed QEMU argv to loopback-only, at the point Driver#execute actually
# shells out to qemu-system-*, so it applies regardless of which code path built the string.
#
# Loaded unconditionally from every guest Vagrantfile via require_relative, before `vagrant
# up` starts QEMU, so no guest can accidentally expose SSH/WinRM/RDP to the LAN.

module VagrantPlugins
  module QEMU
    class Driver
      module ForceLoopbackHostfwd
        LOOPBACK = "127.0.0.1"

        def execute(*cmd, **opts, &block)
          cmd = cmd.map do |arg|
            if arg.is_a?(String)
              arg.gsub(/hostfwd=(tcp|udp)::/, "hostfwd=\\1:#{LOOPBACK}:")
            else
              arg
            end
          end
          super(*cmd, **opts, &block)
        end
      end

      prepend ForceLoopbackHostfwd
    end
  end
end
