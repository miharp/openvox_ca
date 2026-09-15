# frozen_string_literal: true

require 'open3'

module PuppetX
  module OpenvoxCa
    # Resolves Puppet settings on the target by asking the agent's own
    # `puppet config print`, so the tasks follow whatever the deployment has
    # configured instead of assuming default paths.
    module PuppetSettings
      CANDIDATES = [
        '/opt/puppetlabs/bin/puppet',
        'C:/Program Files/Puppet Labs/Puppet/bin/puppet.bat',
      ].freeze

      module_function

      def puppet_bin
        from_path = ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).map { |d| File.join(d, 'puppet') }.find { |p| File.executable?(p) }
        from_path || CANDIDATES.find { |p| File.exist?(p) } || raise('puppet executable not found on PATH or in the standard locations')
      end

      # Hash of setting name => value for the requested settings, read from the
      # given section (`server` for the CA host, `agent` elsewhere).
      def print(names, section: 'agent')
        out, err, status = Open3.capture3(puppet_bin, 'config', 'print', '--section', section, *names)
        raise "puppet config print failed: #{err.strip}" unless status.success?

        out.each_line.with_object({}) do |line, acc|
          key, value = line.chomp.split(' = ', 2)
          acc[key] = value if key && value
        end
      end
    end
  end
end
