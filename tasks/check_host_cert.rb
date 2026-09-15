#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'

params = JSON.parse($stdin.read)
lib = File.join(params['_installdir'], 'openvox_ca', 'lib', 'puppet_x', 'openvox_ca')
require File.join(lib, 'inspect')
require File.join(lib, 'puppet_settings')

begin
  settings = PuppetX::OpenvoxCa::PuppetSettings.print(%w[localcacert hostcert hostcrl certname], section: 'agent')
  report = PuppetX::OpenvoxCa::Inspect.host_report(settings, warn_days: params.fetch('warn_days', 90))
  report['certname'] = settings['certname']
  puts JSON.generate(report)
rescue PuppetX::OpenvoxCa::Inspect::MissingFiles => e
  puts JSON.generate({ '_error' => { 'msg' => e.message, 'kind' => 'openvox_ca/missing-files', 'details' => {} } })
  exit 1
rescue StandardError => e
  puts JSON.generate({ '_error' => { 'msg' => e.message, 'kind' => 'openvox_ca/check_host_cert', 'details' => {} } })
  exit 1
end
