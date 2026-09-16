#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'
require 'open3'

params = JSON.parse($stdin.read)
lib = File.join(params['_installdir'], 'openvox_ca', 'lib', 'puppet_x', 'openvox_ca')
%w[inspect extend distribute puppet_settings].each { |f| require File.join(lib, f) }

begin
  settings = PuppetX::OpenvoxCa::PuppetSettings.print(%w[localcacert hostcrl certname], section: 'agent')
  report = PuppetX::OpenvoxCa::Distribute.remove(settings)
  run = nil
  if params.fetch('trigger_run', true)
    out, err, status = Open3.capture3(PuppetX::OpenvoxCa::PuppetSettings.puppet_bin, 'agent', '--test', '--noop')
    run = { 'exit_code' => status.exitstatus, 'output' => (out + err).lines.last(5).join.strip }
  end
  # The agent fetches the bundle and the CRL separately, so check each file
  # that was removed. A run that failed later, for example on the catalog, is
  # not a distribution failure as long as both copies are back and parse.
  items = PuppetX::OpenvoxCa::Inspect.bundle_items(settings['localcacert'], kind: 'local_ca_copy', warn_days: 0)
  items.concat(PuppetX::OpenvoxCa::Inspect.crl_items(settings['hostcrl'], warn_days: 0)) if settings['hostcrl']
  missing = report['removed'].reject { |p| File.exist?(p) }
  fetched = !items.empty? && missing.empty? && items.any? { |i| i['kind'] == 'local_ca_copy' }
  puts JSON.generate(report.merge('status' => fetched ? 'changed' : 'removed', 'certname' => settings['certname'], 'agent_run' => run, 'fetched' => fetched, 'missing' => missing, 'items' => items))
  exit 1 if params.fetch('trigger_run', true) && !fetched
rescue StandardError => e
  puts JSON.generate({ '_error' => { 'msg' => "#{e.class}: #{e.message}", 'kind' => 'openvox_ca/remove_localcacert', 'details' => {} } })
  exit 1
end
