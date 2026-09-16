# frozen_string_literal: true

require 'fileutils'
require 'time'
require_relative 'inspect'
require_relative 'extend'

module PuppetX
  module OpenvoxCa
    # Agent-side handling of the CA bundle and CRL: install copies pushed from
    # the CA host, or remove the local copies so the next agent run fetches
    # fresh ones. Pure Ruby with no Puppet dependency.
    module Distribute
      class Error < StandardError; end

      module_function

      # Writes the bundle to `localcacert` and, when given, the CRL to `hostcrl`,
      # after checking that both parse and backing up whatever was there.
      # Returns the files written, the backups made, and a report of the
      # installed bundle.
      def install(settings, bundle_pem, crl_pem = nil, now: Time.now)
        certs = bundle_pem.to_s.scan(Inspect::CERT_PATTERN)
        raise Error, 'The bundle holds no certificates' if certs.empty?

        certs.each { |pem| OpenSSL::X509::Certificate.new(pem) }
        if crl_pem
          crls = crl_pem.to_s.scan(Inspect::CRL_PATTERN)
          raise Error, 'The CRL holds no CRL' if crls.empty?

          crls.each { |pem| OpenSSL::X509::CRL.new(pem) }
        end

        writes = { settings['localcacert'] => bundle_pem }
        writes[settings['hostcrl']] = crl_pem if crl_pem && settings['hostcrl']
        outcome = write_all(writes, now)
        outcome.merge('items' => Inspect.bundle_items(settings['localcacert'], kind: 'local_ca_copy', warn_days: 0, now: now))
      end

      # Moves `localcacert` and `hostcrl` aside so the agent fetches new copies
      # on its next run. Returns the backups made.
      def remove(settings, now: Time.now)
        moved = Extend.move_aside([settings['localcacert'], settings['hostcrl']].compact, now: now)
        { 'backups' => moved.values, 'removed' => moved.keys }
      end

      def write_all(writes, now)
        backups = Extend.backup(writes.keys, now: now)
        writes.each { |path, content| Extend.write_atomically(path, content) }
        { 'written' => writes.keys, 'backups' => backups }
      end
    end
  end
end
