#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'

params = JSON.parse($stdin.read)
lib = File.join(params['_installdir'], 'openvox_ca', 'lib', 'puppet_x', 'openvox_ca')
require File.join(lib, 'inspect')
require File.join(lib, 'puppet_settings')

begin
  names = %w[cadir cacert cakey rootkey cacrl localcacert hostcert hostcrl certname]
  settings = PuppetX::OpenvoxCa::PuppetSettings.print(names, section: params.fetch('section', 'server'))
  report = PuppetX::OpenvoxCa::Inspect.ca_report(settings, warn_days: params.fetch('warn_days', 90))
  report['certname'] = settings['certname']
  puts JSON.generate(report)
rescue StandardError => e
  puts JSON.generate({ '_error' => { 'msg' => e.message, 'kind' => 'openvox_ca/check_ca', 'details' => {} } })
  exit 1
end
