#!/opt/puppetlabs/puppet/bin/ruby
# frozen_string_literal: true

require 'json'
require 'open3'
require 'fileutils'

params = JSON.parse($stdin.read)
lib = File.join(params['_installdir'], 'openvox_ca', 'lib', 'puppet_x', 'openvox_ca')
%w[inspect extend puppet_settings service].each { |f| require File.join(lib, f) }

def fail_task(message, kind, details = {})
  puts JSON.generate({ '_error' => { 'msg' => message, 'kind' => kind, 'details' => details } })
  exit 1
end

moved = {}

begin
  warning = PuppetX::OpenvoxCa::Service.refuse_if_running!(force: params.fetch('force', false))
  puppetserver = PuppetX::OpenvoxCa::Service.puppetserver_bin || raise('puppetserver executable not found')

  names = %w[certname hostcert hostprivkey hostpubkey signeddir]
  settings = PuppetX::OpenvoxCa::PuppetSettings.print(names, section: 'server')
  certname = settings['certname']
  old_cert_path = settings['hostcert']
  old_names = if File.exist?(old_cert_path)
                cert = PuppetX::OpenvoxCa::Inspect.certificates(old_cert_path).first
                ext = cert.extensions.find { |e| e.oid == 'subjectAltName' }
                ext ? ext.value.split(',').map(&:strip) : []
              else
                []
              end

  candidates = [settings['hostcert'], settings['hostprivkey'], settings['hostpubkey'], File.join(settings['signeddir'], "#{certname}.pem")]
  moved = PuppetX::OpenvoxCa::Extend.move_aside(candidates)
  backups = moved.values

  cmd = [puppetserver, 'ca', 'generate', '--certname', certname, '--ca-client']
  alt_names = params['dns_alt_names']
  cmd += ['--subject-alt-names', alt_names.join(',')] if alt_names && !alt_names.empty?
  out, err, status = Open3.capture3(*cmd)
  out, err, status = Open3.capture3(*cmd, '--force') if !status.success? && (out + err).include?('--force')
  raise "puppetserver ca generate failed: #{(out + err).strip}" unless status.success?

  fresh = PuppetX::OpenvoxCa::Inspect.certificates(settings['hostcert']).first
  moved = {}
  puts JSON.generate({
                       'status' => 'changed',
                       'certname' => certname,
                       'old_alt_names' => old_names,
                       'alt_names' => alt_names || [],
                       'not_after' => fresh.not_after.utc.iso8601,
                       'backups' => backups,
                       'warning' => warning,
                       'output' => out.strip,
                     })
rescue StandardError => e
  # Put the old certificate and key back so the host is no worse off than
  # before the attempt; a failed generate leaves nothing usable behind.
  restored = []
  not_restored = []
  moved.each do |original, backup|
    next if File.exist?(original)

    begin
      FileUtils.mv(backup, original)
      restored << original
    rescue SystemCallError
      not_restored << backup
    end
  end
  message = "#{e.class}: #{e.message}"
  message += ". Restored #{restored.join(', ')}" unless restored.empty?
  message += ". Could not restore: #{not_restored.join(', ')}" unless not_restored.empty?
  fail_task(message, 'openvox_ca/regen_primary_cert', { 'restored' => restored, 'not_restored' => not_restored })
end
