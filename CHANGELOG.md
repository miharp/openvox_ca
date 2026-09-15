# Changelog

All notable changes to this project will be documented in this file.

## v0.3.0

The `openvox_ca::distribute` plan with the `read_ca_bundle`, `upload_ca`, and `remove_localcacert`
tasks. `refetch` is the default strategy; `upload` is for hosts that cannot reach the server. Lab-verified
against agents whose CA copy had already expired.

## v0.2.0

The `openvox_ca::extend` plan with the `extend_ca`, `regen_primary_cert`, and `refresh_puppetdb_ssl`
tasks. Verified on the lab: single-layout CA extended to 15 years, server certificate regenerated with
alt names and the CA CLI extension, OpenVoxDB refreshed, agents ran clean afterwards.

## v0.1.0

Read-only checks: the `openvox_ca::check` plan with the `check_ca` and `check_host_cert` tasks.
Verified against a three-node OpenVox 8 lab.

## v0.0.1

Repository skeleton only: scaffold, CI, and release workflow. No plans or tasks yet.
