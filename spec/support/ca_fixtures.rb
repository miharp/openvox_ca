# frozen_string_literal: true

require 'openssl'
require 'fileutils'
require 'tmpdir'

# Builds throwaway certificate authorities laid out the way OpenVox Server's
# `puppetserver ca setup` lays them out, so specs can exercise both the
# single-certificate layout and the root plus intermediate bundle without a
# server. Keys are 2048-bit RSA to keep the suite fast.
module CaFixtures
  CA_EXTENSIONS = [
    ['basicConstraints', 'CA:TRUE', true],
    ['keyUsage', 'keyCertSign, cRLSign', true],
    ['subjectKeyIdentifier', 'hash', false],
    ['nsComment', 'Puppet Server Internal Certificate', false],
    ['authorityKeyIdentifier', 'keyid:always', false],
  ].freeze

  HOST_EXTENSIONS = [
    ['basicConstraints', 'CA:FALSE', true],
    ['nsComment', 'Puppet Server Internal Certificate', false],
    ['authorityKeyIdentifier', 'keyid:always', false],
    ['extendedKeyUsage', 'serverAuth, clientAuth', true],
    ['keyUsage', 'keyEncipherment, digitalSignature', true],
    ['subjectKeyIdentifier', 'hash', false],
  ].freeze

  DAY = 60 * 60 * 24

  # Paths for one fixture, mirroring the settings the tasks read from
  # `puppet config print`.
  Layout = Struct.new(:dir, :cadir, :cacert, :cakey, :rootkey, :cacrl, :infra_crl,
                      :localcacert, :hostcert, :hostprivkey, :hostcrl, :certname,
                      keyword_init: true) do
    def settings
      {
        'cadir' => cadir, 'cacert' => cacert, 'cakey' => cakey, 'rootkey' => rootkey,
        'cacrl' => cacrl, 'localcacert' => localcacert, 'hostcert' => hostcert,
        'hostprivkey' => hostprivkey, 'hostcrl' => hostcrl, 'certname' => certname,
      }
    end
  end

  module_function

  # A CA whose bundle holds a single self-signed certificate.
  def single_ca(dir = Dir.mktmpdir('openvox_ca_single'), ca_days: 365 * 15, host_days: 365 * 5, certname: 'puppet.example.com')
    layout = layout_for(dir, certname)
    ca_key = OpenSSL::PKey::RSA.new(2048)
    ca_cert = self_signed(ca_key, 'Puppet CA: puppet.example.com', ca_days, serial: 1)
    ca_crl = crl_for(ca_cert, ca_key, ca_days)
    host_key, host_cert = host(ca_cert, ca_key, certname, host_days, serial: 2)

    write(layout.cacert, ca_cert.to_pem)
    write(layout.cakey, ca_key.to_pem, 0o640)
    write(layout.cacrl, ca_crl.to_pem)
    write(layout.infra_crl, ca_crl.to_pem)
    write(layout.localcacert, ca_cert.to_pem)
    write(layout.hostcert, host_cert.to_pem)
    write(layout.hostprivkey, host_key.to_pem, 0o640)
    write(layout.hostcrl, ca_crl.to_pem)
    layout
  end

  # The default layout: an intermediate signing CA issued by a root, with the
  # bundle ordered intermediate first, root second, and both keys on disk.
  def intermediate_ca(dir = Dir.mktmpdir('openvox_ca_intermediate'), ca_days: 365 * 15, host_days: 365 * 5, certname: 'puppet.example.com', keep_root_key: true)
    layout = layout_for(dir, certname)
    root_key = OpenSSL::PKey::RSA.new(2048)
    root_cert = self_signed(root_key, 'Puppet Root CA: 0123456789abcdef', ca_days, serial: 1)
    root_crl = crl_for(root_cert, root_key, ca_days)
    int_key = OpenSSL::PKey::RSA.new(2048)
    int_cert = signed_ca(int_key, 'Puppet CA: puppet.example.com', root_cert, root_key, ca_days, serial: 2)
    int_crl = crl_for(int_cert, int_key, ca_days)
    host_key, host_cert = host(int_cert, int_key, certname, host_days, serial: 3)

    write(layout.cacert, int_cert.to_pem + root_cert.to_pem)
    write(layout.cakey, int_key.to_pem, 0o640)
    write(layout.rootkey, root_key.to_pem, 0o640) if keep_root_key
    write(layout.cacrl, int_crl.to_pem + root_crl.to_pem)
    write(layout.infra_crl, int_crl.to_pem + root_crl.to_pem)
    write(layout.localcacert, int_cert.to_pem + root_cert.to_pem)
    write(layout.hostcert, host_cert.to_pem)
    write(layout.hostprivkey, host_key.to_pem, 0o640)
    write(layout.hostcrl, int_crl.to_pem + root_crl.to_pem)
    layout
  end

  def layout_for(dir, certname)
    cadir = File.join(dir, 'puppetserver', 'ca')
    ssldir = File.join(dir, 'puppet', 'ssl')
    Layout.new(
      dir: dir, cadir: cadir, certname: certname,
      cacert: File.join(cadir, 'ca_crt.pem'), cakey: File.join(cadir, 'ca_key.pem'),
      rootkey: File.join(cadir, 'root_key.pem'), cacrl: File.join(cadir, 'ca_crl.pem'),
      infra_crl: File.join(cadir, 'infra_crl.pem'),
      localcacert: File.join(ssldir, 'certs', 'ca.pem'),
      hostcert: File.join(ssldir, 'certs', "#{certname}.pem"),
      hostprivkey: File.join(ssldir, 'private_keys', "#{certname}.pem"),
      hostcrl: File.join(ssldir, 'crl.pem')
    )
  end

  def write(path, content, mode = 0o644)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, content)
    File.chmod(mode, path)
  end

  def base_cert(subject, days, serial:)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.new([['CN', subject]])
    cert.not_before = Time.now - DAY
    cert.not_after = Time.now + (days * DAY)
    cert
  end

  def add_extensions(cert, issuer_cert, extensions)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = issuer_cert
    extensions.each { |name, value, critical| cert.add_extension(ef.create_extension(name, value, critical)) }
  end

  def self_signed(key, subject, days, serial:)
    cert = base_cert(subject, days, serial: serial)
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    add_extensions(cert, cert, CA_EXTENSIONS)
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
  end

  def signed_ca(key, subject, issuer_cert, issuer_key, days, serial:)
    cert = base_cert(subject, days, serial: serial)
    cert.issuer = issuer_cert.subject
    cert.public_key = key.public_key
    add_extensions(cert, issuer_cert, CA_EXTENSIONS)
    cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
  end

  def host(issuer_cert, issuer_key, certname, days, serial:)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = base_cert(certname, days, serial: serial)
    cert.issuer = issuer_cert.subject
    cert.public_key = key.public_key
    add_extensions(cert, issuer_cert, HOST_EXTENSIONS)
    cert.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    [key, cert]
  end

  def crl_for(cert, key, days, revoked: [])
    crl = OpenSSL::X509::CRL.new
    crl.version = 1
    crl.issuer = cert.subject
    crl.last_update = Time.now - DAY
    crl.next_update = Time.now + (days * DAY)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.issuer_certificate = cert
    crl.add_extension(ef.create_extension('authorityKeyIdentifier', 'keyid:always', false))
    crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', OpenSSL::ASN1::Integer(0)))
    revoked.each do |serial|
      entry = OpenSSL::X509::Revoked.new
      entry.serial = serial
      entry.time = Time.now - DAY
      crl.add_revoked(entry)
    end
    crl.sign(key, OpenSSL::Digest.new('SHA256'))
  end
end
