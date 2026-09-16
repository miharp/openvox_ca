# frozen_string_literal: true

require 'spec_helper_acceptance'

# Installs OpenVox Server on the test node with a one-second ca_ttl so the CA it
# generates on first start is expired straight away, then runs the module's
# tasks the way OpenBolt would (JSON on stdin, files under _installdir) and
# checks that an agent run works afterwards.
describe 'extending an expired CA' do
  def installdir
    '/tmp/openvox_ca_acceptance'
  end

  def module_root
    File.expand_path('../..', __dir__)
  end

  def task(name, params, installdir)
    json = JSON.generate(params.merge('_installdir' => installdir))
    result = shell("echo '#{json}' | /opt/puppetlabs/puppet/bin/ruby #{installdir}/openvox_ca/tasks/#{name}.rb", acceptable_exit_codes: [0, 1])
    [result.exit_code, JSON.parse(result.stdout)]
  end

  before(:all) do
    shell("mkdir -p #{installdir}/openvox_ca")
    %w[lib tasks].each { |d| scp_to(default, File.join(module_root, d), "#{installdir}/openvox_ca/") }

    install_package(default, 'openvox-server')
    shell('/opt/puppetlabs/bin/puppet config set --section server ca_ttl 1')
    shell("/opt/puppetlabs/bin/puppet config set --section main certname #{fact('networking.fqdn')}")
    shell("/opt/puppetlabs/bin/puppet config set --section main server #{fact('networking.fqdn')}")
    shell('systemctl start puppetserver')
    # The CA certificate the server just made is valid for one second, so the
    # server itself cannot serve TLS with it, but the files are on disk. Put
    # ca_ttl back to its default so the certificates made from here on, such
    # as the regenerated server certificate, get a normal lifetime.
    shell('systemctl stop puppetserver')
    shell('/opt/puppetlabs/bin/puppet config delete --section server ca_ttl')
  end

  it 'starts from an expired single-certificate CA' do
    code, report = task('check_ca', {}, installdir)
    expect(code).to eq(0)
    expect(report['layout']).to eq('single')
    expect(report['status']).to eq('expired')
    expect(report['items'].find { |i| i['kind'] == 'ca_cert' }['status']).to eq('expired')
  end

  it 'refuses to run while puppetserver is active unless forced' do
    shell('systemctl start puppetserver', acceptable_exit_codes: [0, 1])
    code, report = task('extend_ca', { 'ttl' => '5y' }, installdir)
    shell('systemctl stop puppetserver')
    expect(code).to eq(1)
    expect(report['_error']['msg']).to match(%r{running})
  end

  it 'extends the CA, leaving the still-valid CRLs alone' do
    code, report = task('extend_ca', { 'ttl' => '5y' }, installdir)
    expect(code).to eq(0)
    expect(report['status']).to eq('changed')
    expect(report['certificates'].length).to eq(1)
    # The server gives its CRLs their own multi-year lifetime, independent of
    # ca_ttl, so they are not expired here and must be left untouched.
    expect(report['crls'].map { |c| c['resigned'] }).to all(be(false))
    expect(report['backups'].length).to be >= 3
  end

  it 'regenerates the server certificate, which expired with the CA' do
    code, report = task('regen_primary_cert', { 'dns_alt_names' => ['puppet', fact('networking.fqdn')] }, installdir)
    expect(code).to eq(0)
    expect(report['status']).to eq('changed')
  end

  it 'reports everything ok afterwards' do
    _code, report = task('check_ca', {}, installdir)
    expect(report['status']).to eq('ok')
  end

  it 'lets the server start and an agent run succeed' do
    shell('systemctl start puppetserver')
    shell('for i in $(seq 1 60); do curl -sSf --insecure https://127.0.0.1:8140/status/v1/simple && break; sleep 5; done')
    result = shell('/opt/puppetlabs/bin/puppet agent -t --detailed-exitcodes', acceptable_exit_codes: [0, 1, 2, 4, 6])
    expect(result.exit_code).to eq(0).or eq(2)
  end

  it 'refetches the CA bundle after the local copy is removed' do
    code, report = task('remove_localcacert', { 'trigger_run' => true }, installdir)
    expect(code).to eq(0)
    expect(report['fetched']).to be(true)
    expect(report['backups'].length).to eq(2)
    # The CA was extended above with a five-year TTL; the refetched copy must carry that expiry.
    expect(Time.parse(report['items'].first['not_after'])).to be_within(60 * 60).of(Time.now + (5 * 365 * 24 * 60 * 60))
  end

  it 'installs an uploaded bundle' do
    _code, source = task('read_ca_bundle', {}, installdir)
    code, report = task('upload_ca', { 'bundle' => source['bundle'], 'crl' => source['crl'], 'restart_agent' => false }, installdir)
    expect(code).to eq(0)
    expect(report['written'].length).to eq(2)
    expect(report['items'].first['subject']).to eq(source['certificates'].first['subject'])
  end
end
