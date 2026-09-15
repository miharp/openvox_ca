# frozen_string_literal: true

require 'open3'

module PuppetX
  module OpenvoxCa
    # Small helpers for the tasks that change state on the CA host.
    module Service
      module_function

      # True when systemd reports the unit active. Callers should check
      # `systemctl` first; without it this is always false.
      def active?(unit)
        return false unless systemctl

        out, _err, _status = Open3.capture3(systemctl, 'is-active', unit)
        out.strip == 'active'
      end

      def systemctl
        %w[/usr/bin/systemctl /bin/systemctl].find { |p| File.executable?(p) }
      end

      def puppetserver_bin
        %w[/opt/puppetlabs/bin/puppetserver /usr/local/bin/puppetserver].find { |p| File.executable?(p) }
      end

      def puppetdb_bin
        %w[/opt/puppetlabs/bin/puppetdb /usr/local/bin/puppetdb].find { |p| File.executable?(p) }
      end

      # Raises unless the CA service is stopped, or `force` is set. A missing
      # systemctl is reported but not fatal.
      def refuse_if_running!(force: false)
        return 'systemctl not found; could not confirm that puppetserver is stopped' unless systemctl
        return nil unless active?('puppetserver')
        return 'puppetserver is active; proceeding because force was set' if force

        raise 'puppetserver is running; stop it first or pass force=true'
      end
    end
  end
end
