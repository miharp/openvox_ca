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

  describe '.overall_status' do
    it 'ranks expired over warn over ok' do
      expect(inspect.overall_status([{ 'status' => 'ok' }, { 'status' => 'warn' }])).to eq('warn')
      expect(inspect.overall_status([{ 'status' => 'warn' }, { 'status' => 'expired' }])).to eq('expired')
      expect(inspect.overall_status([])).to eq('ok')
    end
  end
end
