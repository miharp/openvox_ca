# frozen_string_literal: true

require 'spec_helper'
require_relative '../../../support/ca_fixtures'
require_relative '../../../../lib/puppet_x/openvox_ca/extend'

describe PuppetX::OpenvoxCa::Extend do
  def extend
    described_class
  end

  def inspect
    PuppetX::OpenvoxCa::Inspect
  end

  def ttl
    15 * 365 * 24 * 60 * 60
  end

  def now
    @now ||= Time.now
  end

  def certs_from(pem)
    pem.scan(inspect::CERT_PATTERN).map { |p| OpenSSL::X509::Certificate.new(p) }
  end

  def crls_from(pem)
    pem.scan(inspect::CRL_PATTERN).map { |p| OpenSSL::X509::CRL.new(p) }
  end

  describe '.parse_ttl' do
    it 'accepts the gem duration format and bare seconds' do
      expect(extend.parse_ttl('15y')).to eq(15 * 365 * 86_400)
      expect(extend.parse_ttl('30d')).to eq(30 * 86_400)
      expect(extend.parse_ttl('10')).to eq(10)
      expect(extend.parse_ttl(42)).to eq(42)
    end

    it 'rejects junk and zero' do
      expect { extend.parse_ttl('soon') }.to raise_error(described_class::Error, %r{Invalid TTL})
      expect { extend.parse_ttl('0d') }.to raise_error(described_class::Error, %r{positive})
    end
  end

  describe 'single-certificate layout' do
    let(:layout) { CaFixtures.single_ca(ca_days: 20, revoked: [7]) }
    let(:old) { inspect.certificates(layout.cacert).first }
    let(:result) { extend.compute(layout.settings, ttl_seconds: ttl, now: now) }
    let(:fresh) { OpenSSL::X509::Certificate.new(result['bundle_pem']) }

    after { FileUtils.rm_rf(layout.dir) }

    it 'keeps subject, issuer, serial, public key, and extensions' do
      expect(result['layout']).to eq('single')
      expect(fresh.subject).to eq(old.subject)
      expect(fresh.issuer).to eq(old.issuer)
      expect(fresh.serial).to eq(old.serial)
      expect(fresh.public_key.to_der).to eq(old.public_key.to_der)
      expect(fresh.extensions.map(&:to_s)).to eq(old.extensions.map(&:to_s))
    end

    it 'moves the validity window and signs with the CA key' do
      expect(fresh.not_after).to be_within(2).of(now + ttl)
      expect(fresh.not_before).to be_within(2).of(now - 86_400)
      expect(fresh.verify(fresh.public_key)).to be(true)
      expect(result['certificates'].first).to include('self_signed' => true, 'signed_by' => old.subject.to_s, 'key_file' => layout.cakey)
    end

    it 'leaves valid CRLs alone by default' do
      items = result['crl_files'].values.flat_map { |f| f['items'] }
      expect(items.map { |i| i['resigned'] }).to all(be(false))
      expect(result['crl_files'][layout.cacrl]['pem']).to eq(File.read(layout.cacrl))
    end

    it 're-signs every CRL on request, keeping revoked entries and bumping crlNumber' do
      all = extend.compute(layout.settings, ttl_seconds: ttl, crls: :all, now: now)
      crl = OpenSSL::X509::CRL.new(all['crl_files'][layout.cacrl]['pem'])
      expect(crl.revoked.map(&:serial)).to eq([7])
      expect(extend.crl_number(crl)).to eq(1)
      expect(crl.next_update).to be_within(2).of(now + ttl)
      expect(crl.verify(fresh.public_key)).to be(true)
    end

    it 'still validates the existing host certificate' do
      host = inspect.certificates(layout.hostcert).first
      store = OpenSSL::X509::Store.new
      store.add_cert(fresh)
      expect(store.verify(host)).to be(true)
    end
  end

  describe 'expired single-certificate layout' do
    let(:layout) { CaFixtures.single_ca(ca_days: -2, host_days: 365) }
    let(:result) { extend.compute(layout.settings, ttl_seconds: ttl, now: now) }

    after { FileUtils.rm_rf(layout.dir) }

    it 're-signs the expired CRLs without being asked' do
      items = result['crl_files'].values.flat_map { |f| f['items'] }
      expect(items.length).to eq(2)
      expect(items.map { |i| i['resigned'] }).to all(be(true))
    end
  end

  describe 'intermediate layout' do
    let(:layout) { CaFixtures.intermediate_ca(ca_days: -1, revoked: [9]) }
    let(:old) { inspect.certificates(layout.cacert) }
    let(:result) { extend.compute(layout.settings, ttl_seconds: ttl, now: now) }
    let(:fresh) { certs_from(result['bundle_pem']) }

    after { FileUtils.rm_rf(layout.dir) }

    it 'keeps the bundle order and signs the intermediate with the root key' do
      expect(result['layout']).to eq('intermediate')
      expect(fresh.map(&:subject)).to eq(old.map(&:subject))
      expect(result['certificates'].map { |c| c['signed_by'] }).to eq([old[1].subject.to_s, old[1].subject.to_s])
      expect(result['certificates'].map { |c| c['key_file'] }).to eq([layout.cakey, layout.rootkey])
    end

    it 'produces a chain that verifies and still validates the host certificate' do
      store = OpenSSL::X509::Store.new
      store.add_cert(fresh[1])
      expect(store.verify(fresh[0])).to be(true)
      store.add_cert(fresh[0])
      expect(store.verify(inspect.certificates(layout.hostcert).first)).to be(true)
    end

    it 're-signs each expired CRL with the key of the CA that issued it' do
      pems = crls_from(result['crl_files'][layout.cacrl]['pem'])
      expect(pems.length).to eq(2)
      expect(pems[0].verify(fresh[0].public_key)).to be(true)
      expect(pems[1].verify(fresh[1].public_key)).to be(true)
      expect(pems[0].revoked.map(&:serial)).to eq([9])
    end
  end

  describe 'refusals' do
    it 'refuses an externally issued CA and names it' do
      layout = CaFixtures.intermediate_ca(keep_root_key: false)
      expect { extend.compute(layout.settings, ttl_seconds: ttl) }.to raise_error(described_class::Error, %r{No private key on disk for /CN=Puppet Root CA})
      FileUtils.rm_rf(layout.dir)
    end

    it 'refuses a bundle with more than two certificates' do
      layout = CaFixtures.intermediate_ca
      File.write(layout.cacert, File.read(layout.cacert) + File.read(layout.hostcert))
      expect { extend.compute(layout.settings, ttl_seconds: ttl) }.to raise_error(described_class::Error, %r{holds 3 certificates})
      FileUtils.rm_rf(layout.dir)
    end

    it 'refuses a CRL that was not issued by this CA' do
      layout = CaFixtures.single_ca
      other = CaFixtures.single_ca
      File.write(layout.cacrl, File.read(other.cacrl))
      expect { extend.compute(layout.settings, ttl_seconds: ttl) }.to raise_error(described_class::Error, %r{does not belong to this CA})
      FileUtils.rm_rf(layout.dir)
      FileUtils.rm_rf(other.dir)
    end
  end

  describe '.apply' do
    let(:layout) { CaFixtures.intermediate_ca(ca_days: -1) }
    let(:result) { extend.compute(layout.settings, ttl_seconds: ttl, now: now) }

    after { FileUtils.rm_rf(layout.dir) }

    it 'writes the bundle and CRLs to every location, with backups, preserving mode' do
      File.chmod(0o640, layout.cacert)
      outcome = extend.apply(layout.settings, result, now: now)
      expect(outcome['written']).to contain_exactly(layout.cacert, layout.localcacert, layout.cacrl, layout.infra_crl, layout.hostcrl)
      expect(outcome['backups'].length).to eq(5)
      expect(outcome['backups']).to all(satisfy { |b| File.exist?(b) })
      expect(File.read(layout.cacert)).to eq(result['bundle_pem'])
      expect(File.read(layout.localcacert)).to eq(result['bundle_pem'])
      expect(File.read(layout.hostcrl)).to eq(File.read(layout.cacrl))
      expect(File.stat(layout.cacert).mode & 0o777).to eq(0o640)
      expect(inspect.ca_report(layout.settings)['status']).to eq('ok')
    end
  end
end
