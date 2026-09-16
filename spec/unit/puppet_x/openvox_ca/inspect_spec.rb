# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../support/ca_fixtures'
require_relative '../../../../lib/puppet_x/openvox_ca/inspect'

describe PuppetX::OpenvoxCa::Inspect do
  let(:inspect) { described_class }

  describe 'single-certificate layout' do
    let(:layout) { CaFixtures.single_ca }
    let(:report) { inspect.ca_report(layout.settings, warn_days: 90) }

    after { FileUtils.rm_rf(layout.dir) }

    it 'detects the layout' do
      expect(report['layout']).to eq('single')
    end

    it 'finds the CA key for the CA certificate' do
      ca = report['items'].find { |i| i['kind'] == 'ca_cert' }
      expect(ca['key_present']).to be(true)
      expect(ca['key_file']).to eq(layout.cakey)
      expect(ca['self_signed']).to be(true)
    end

    it 'reports the CA CRL, the infra CRL, the host CRL, the host certificate, and the local CA copy' do
      kinds = report['items'].map { |i| i['kind'] }
      expect(kinds).to include('host_cert', 'local_ca_copy')
      expect(kinds.count('crl')).to eq(3)
    end

    it 'is ok with fifteen years left' do
      expect(report['status']).to eq('ok')
      expect(report['external_ca_subjects']).to be_empty
    end
  end

  describe 'intermediate layout' do
    let(:layout) { CaFixtures.intermediate_ca }
    let(:report) { inspect.ca_report(layout.settings, warn_days: 90) }
    let(:ca_items) { report['items'].select { |i| i['kind'] == 'ca_cert' } }

    after { FileUtils.rm_rf(layout.dir) }

    it 'detects the layout and keeps bundle order' do
      expect(report['layout']).to eq('intermediate')
      expect(ca_items.map { |i| i['self_signed'] }).to eq([false, true])
    end

    it 'matches each certificate to its own key' do
      expect(ca_items.map { |i| i['key_file'] }).to eq([layout.cakey, layout.rootkey])
    end

    it 'reports two CRLs for each of the three CRL files' do
      crls = report['items'].select { |i| i['kind'] == 'crl' }
      expect(crls.length).to eq(6)
      expect(crls.map { |i| i['file'] }.uniq.length).to eq(3)
    end
  end

  describe 'an externally issued CA' do
    let(:layout) { CaFixtures.intermediate_ca(keep_root_key: false) }
    let(:report) { inspect.ca_report(layout.settings, warn_days: 90) }

    after { FileUtils.rm_rf(layout.dir) }

    it 'names the certificate whose key is missing' do
      expect(report['external_ca_subjects']).to eq(['/CN=Puppet Root CA: 0123456789abcdef'])
    end
  end

  describe 'expiry classification' do
    let(:layout) { CaFixtures.single_ca(ca_days: 30, host_days: -1) }
    let(:report) { inspect.ca_report(layout.settings, warn_days: 90) }

    after { FileUtils.rm_rf(layout.dir) }

    it 'warns on a CA inside the window and marks the host certificate expired' do
      ca = report['items'].find { |i| i['kind'] == 'ca_cert' }
      host = report['items'].find { |i| i['kind'] == 'host_cert' }
      expect(ca['status']).to eq('warn')
      expect(host['status']).to eq('expired')
      expect(host['days_left']).to be_negative
      expect(report['status']).to eq('expired')
    end
  end

  describe 'issued certificates' do
    let(:layout) { CaFixtures.single_ca }

    before do
      CaFixtures.issue(layout, 'fresh.example.com', days: 365 * 4, serial: 100)
      CaFixtures.issue(layout, 'soon.example.com', days: 30, serial: 101)
      CaFixtures.issue(layout, 'gone.example.com', days: -1, serial: 102)
      CaFixtures.issue(layout, 'revoked.example.com', days: 365, serial: 103, revoke: true)
    end

    after { FileUtils.rm_rf(layout.dir) }

    it 'lists only the due and expired ones by default, with counts for the whole directory' do
      report = inspect.ca_report(layout.settings, warn_days: 90)
      issued = report['items'].select { |i| i['kind'] == 'issued_cert' }
      expect(issued.map { |i| i['certname'] }).to eq(%w[gone.example.com soon.example.com])
      expect(issued.map { |i| i['status'] }).to eq(%w[expired warn])
      expect(report['issued']).to eq('total' => 5, 'ok' => 3, 'warn' => 1, 'expired' => 1, 'revoked' => 1)
    end

    it 'lists every issued certificate with issued: :all, including the server itself, and marks revoked ones' do
      report = inspect.ca_report(layout.settings, warn_days: 90, issued: :all)
      issued = report['items'].select { |i| i['kind'] == 'issued_cert' }
      expect(issued.map { |i| i['certname'] }).to eq(%w[fresh.example.com gone.example.com puppet.example.com revoked.example.com soon.example.com])
      expect(issued.find { |i| i['certname'] == 'revoked.example.com' }['revoked']).to be(true)
      expect(issued.count { |i| i['revoked'] }).to eq(1)
      expect(issued.first).not_to have_key('key_present')
    end

    it 'skips the directory with issued: :none' do
      report = inspect.ca_report(layout.settings, warn_days: 90, issued: :none)
      expect(report['items'].map { |i| i['kind'] }).not_to include('issued_cert')
      expect(report['issued']).to be_nil
    end

    it 'does not let an expired issued certificate change the CA status or layout' do
      report = inspect.ca_report(layout.settings, warn_days: 90, issued: :all)
      expect(report['status']).to eq('ok')
      expect(report['layout']).to eq('single')
    end

    it 'copes with a missing signed directory' do
      FileUtils.rm_rf(layout.signeddir)
      report = inspect.ca_report(layout.settings, warn_days: 90)
      expect(report['issued']).to eq('total' => 0, 'ok' => 0, 'warn' => 0, 'expired' => 0, 'revoked' => 0)
    end
  end

  describe 'host report' do
    let(:layout) { CaFixtures.intermediate_ca }
    let(:report) { inspect.host_report(layout.settings, warn_days: 90) }

    after { FileUtils.rm_rf(layout.dir) }

    it 'covers the host certificate, the local CA copy, and the CRL' do
      expect(report['items'].map { |i| i['kind'] }).to eq(%w[host_cert local_ca_copy local_ca_copy crl crl])
      expect(report['status']).to eq('ok')
    end

    it 'does not report key fields for certificates it has no keys for' do
      expect(report['items'].first).not_to have_key('key_present')
    end
  end

  describe 'missing files' do
    it 'raises a clear error when the certificate files are absent' do
      settings = { 'hostcert' => '/nonexistent/host.pem', 'localcacert' => '/nonexistent/ca.pem' }
      expect { inspect.host_report(settings) }.to raise_error(described_class::MissingFiles, %r{--run-as root})
      expect { inspect.ca_report({ 'cacert' => '/nonexistent/ca_crt.pem' }) }.to raise_error(described_class::MissingFiles)
    end

    it 'treats a missing CA key as an external CA rather than missing files' do
      layout = CaFixtures.single_ca
      File.delete(layout.cakey)
      report = inspect.ca_report(layout.settings)
      expect(report['external_ca_subjects']).to eq(['/CN=Puppet CA: puppet.example.com'])
      FileUtils.rm_rf(layout.dir)
    end
  end

  describe 'malformed files' do
    let(:layout) { CaFixtures.single_ca }

    after { FileUtils.rm_rf(layout.dir) }

    it 'refuses to call an empty host certificate healthy' do
      File.write(layout.hostcert, '')
      expect { inspect.host_report(layout.settings) }.to raise_error(described_class::Malformed, %r{holds no certificate})
    end

    it 'refuses an empty CA bundle' do
      File.write(layout.cacert, '')
      expect { inspect.ca_report(layout.settings) }.to raise_error(described_class::Malformed, %r{holds no certificate})
    end

    it 'refuses a truncated CRL' do
      File.write(layout.cacrl, "-----BEGIN X509 CRL-----\ntruncated")
      expect { inspect.ca_report(layout.settings) }.to raise_error(described_class::Malformed, %r{holds no CRL})
    end
  end

  describe '.overall_status' do
    it 'ranks expired over warn over ok' do
      expect(inspect.overall_status([{ 'status' => 'ok' }, { 'status' => 'warn' }])).to eq('warn')
      expect(inspect.overall_status([{ 'status' => 'warn' }, { 'status' => 'expired' }])).to eq('expired')
      expect(inspect.overall_status([])).to eq('ok')
    end
  end
end
