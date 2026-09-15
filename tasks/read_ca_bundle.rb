#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'
require 'base64'

params = JSON.parse($stdin.read)
lib = File.join(params['_installdir'], 'openvox_ca', 'lib', 'puppet_x', 'openvox_ca')
%w[inspect puppet_settings].each { |f| require File.join(lib, f) }

begin
  settings = PuppetX::OpenvoxCa::PuppetSettings.print(%w[cacert cacrl certname], section: params.fetch('section', 'server'))
  bundle = File.read(settings['cacert'])
  crl = File.exist?(settings['cacrl']) ? File.read(settings['cacrl']) : nil
  items = PuppetX::OpenvoxCa::Inspect.bundle_items(settings['cacert'], kind: 'ca_cert', warn_days: 0)
  puts JSON.generate({
                       'certname' => settings['certname'],
                       'bundle' => Base64.strict_encode64(bundle),
                       'crl' => crl && Base64.strict_encode64(crl),
                       'certificates' => items.map { |i| i.slice('subject', 'serial', 'not_after') },
                     })
rescue StandardError => e
  puts JSON.generate({ '_error' => { 'msg' => "#{e.class}: #{e.message}", 'kind' => 'openvox_ca/read_ca_bundle', 'details' => {} } })
  exit 1
end
