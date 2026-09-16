# frozen_string_literal: true

# Canned task results shaped like the real tasks' output.
module PlanFixtures
  CA = 'puppet.example.com'

  def ca_item(status: 'ok', days: 1823)
    { 'kind' => 'ca_cert', 'file' => '/etc/puppetlabs/puppetserver/ca/ca_crt.pem', 'subject' => '/CN=Puppet CA: puppet.example.com',
      'issuer' => '/CN=Puppet CA: puppet.example.com', 'serial' => '1', 'not_before' => '2026-09-15T00:00:00Z',
      'not_after' => '2031-09-12T15:41:28Z', 'days_left' => days, 'status' => status, 'self_signed' => true,
      'key_present' => true, 'key_file' => '/etc/puppetlabs/puppetserver/ca/ca_key.pem', }
  end

  def crl_item(status: 'ok')
    { 'kind' => 'crl', 'file' => '/etc/puppetlabs/puppetserver/ca/ca_crl.pem', 'issuer' => '/CN=Puppet CA: puppet.example.com',
      'last_update' => '2026-09-15T00:00:00Z', 'next_update' => '2031-09-12T15:41:28Z', 'days_left' => 1823,
      'status' => status, 'revoked_count' => 0, }
  end

  def issued_item(certname, status: 'warn', days: 47, revoked: false)
    { 'kind' => 'issued_cert', 'file' => "/etc/puppetlabs/puppetserver/ca/signed/#{certname}.pem", 'subject' => "/CN=#{certname}",
      'issuer' => '/CN=Puppet CA: puppet.example.com', 'serial' => '9', 'not_before' => '2021-01-01T00:00:00Z',
      'not_after' => '2026-11-02T00:00:00Z', 'days_left' => days, 'status' => status, 'self_signed' => false,
      'certname' => certname, 'revoked' => revoked, }
  end

  def ca_report(status: 'ok', layout: 'single', external: [], items: nil, issued: nil)
    { 'status' => status, 'warn_days' => 90, 'checked_at' => '2026-09-16T00:00:00Z', 'layout' => layout,
      'external_ca_subjects' => external, 'issued' => issued,
      'items' => items || [ca_item(status: status), crl_item], 'certname' => CA, }
  end

  def host_report(status: 'ok')
    { 'status' => status, 'warn_days' => 90, 'checked_at' => '2026-09-16T00:00:00Z', 'certname' => 'agent01.example.com',
      'items' => [{ 'kind' => 'host_cert', 'file' => '/etc/puppetlabs/puppet/ssl/certs/agent01.example.com.pem',
                    'subject' => '/CN=agent01.example.com', 'issuer' => '/CN=Puppet CA: puppet.example.com', 'serial' => '3',
                    'not_before' => '2026-09-15T00:00:00Z', 'not_after' => '2031-09-12T15:41:28Z', 'days_left' => 1823,
                    'status' => status, 'self_signed' => false, }], }
  end

  def extend_result(implementation: 'library')
    { 'status' => 'changed', 'implementation' => implementation, 'certname' => CA, 'ttl_seconds' => 473_040_000,
      'layout' => 'single', 'not_after' => '2041-09-12T00:00:00Z',
      'certificates' => [{ 'subject' => '/CN=Puppet CA: puppet.example.com', 'serial' => '1', 'self_signed' => true,
                           'signed_by' => '/CN=Puppet CA: puppet.example.com', 'key_file' => '/etc/puppetlabs/puppetserver/ca/ca_key.pem',
                           'old_not_after' => '2031-09-12T15:41:28Z', 'new_not_after' => '2041-09-12T00:00:00Z', }],
      'crls' => [{ 'issuer' => '/CN=Puppet CA: puppet.example.com', 'revoked_count' => 0, 'old_next_update' => '2031-09-12T15:41:28Z',
                   'new_next_update' => '2031-09-12T15:41:28Z', 'resigned' => false, 'file' => '/etc/puppetlabs/puppetserver/ca/ca_crl.pem', }],
      'planned_writes' => ['/etc/puppetlabs/puppetserver/ca/ca_crt.pem'], 'written' => ['/etc/puppetlabs/puppetserver/ca/ca_crt.pem'],
      'backups' => ['/etc/puppetlabs/puppetserver/ca/ca_crt.pem.20260916T000000Z.bak'], 'warning' => nil, }
  end

  def regen_result
    { 'status' => 'changed', 'certname' => CA, 'old_alt_names' => ['DNS:puppet'], 'alt_names' => %w[puppet puppet.example.com],
      'not_after' => '2031-09-16T00:00:00Z', 'backups' => [], 'warning' => nil, 'output' => '', }
  end

  def distribute_result(kind: 'local_ca_copy')
    { 'status' => 'changed', 'certname' => 'agent01.example.com', 'written' => ['/etc/puppetlabs/puppet/ssl/certs/ca.pem'],
      'backups' => ['/etc/puppetlabs/puppet/ssl/certs/ca.pem.20260916T000000Z.bak'], 'fetched' => true,
      'items' => [{ 'kind' => kind, 'not_after' => '2041-09-12T00:00:00Z', 'subject' => '/CN=Puppet CA: puppet.example.com' },
                  { 'kind' => 'crl', 'next_update' => '2031-09-12T15:41:28Z', 'issuer' => '/CN=Puppet CA: puppet.example.com' },], }
  end
end
