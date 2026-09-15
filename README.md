# openvox_ca

Check, extend, and distribute the OpenVox CA certificate without reissuing agent certificates.

> **Warning:** This module rewrites the certificate authority's own certificate. A mistake here breaks
> authentication for the whole deployment. Back up the CA directory before you run anything that changes
> state, and try the procedure in a test environment first.

## Status

Early development. The read-only `openvox_ca::check` plan works. The extend and distribute plans
described below are the intended interface and will appear as the work progresses.

The module is not on the Forge. To try a release, pin a git tag in your Puppetfile:

```ruby
mod 'openvox_ca',
  git: 'https://github.com/miharp/openvox_ca.git',
  ref: 'v0.1.0'
```

## Usage

Report certificate expiry for the CA host and, optionally, other hosts:

```console
bolt plan run openvox_ca::check ca=puppet.example.com targets=agents
```

The plan runs `openvox_ca::check_ca` on the CA host and `openvox_ca::check_host_cert` on every other
target, prints one line per certificate or CRL sorted by days left, and returns the raw reports.
Anything expiring within `warn_days` (default 90) is marked `warn`; anything already expired is
marked `expired`. The tasks resolve file locations through the target's own `puppet config print`, so
run them with enough privilege to read the CA directory on the CA host and the SSL directory
elsewhere, for example with `--run-as root`.

```text
STATUS   HOST                         KIND           EXPIRES      DAYS  SUBJECT
ok       puppet.example.com           ca_cert        2031-09-12   1823  /CN=Puppet CA: puppet.example.com
ok       puppet.example.com           crl            2031-09-12   1823  /CN=Puppet CA: puppet.example.com
ok       agent01.example.com          host_cert      2031-09-12   1823  /CN=agent01.example.com
ok       agent01.example.com          local_ca_copy  2031-09-12   1823  /CN=Puppet CA: puppet.example.com
```

The CA report also says which layout the bundle has (`single`, or `intermediate` for the root plus
signing certificate pair) and lists any CA certificate whose private key is not on disk, which
means the CA was issued externally and cannot be extended here.

## What it will do

An OpenVox CA certificate is valid for 15 years by default. When it expires, every TLS connection in the
deployment fails at once. Rebuilding the CA is not necessary: re-signing the existing CA certificate with
the same key and subject gives it a new validity period, and every host certificate the CA ever issued
stays valid because the signing key has not changed. Only the CA certificate file changes, and the new
copy then has to reach agents and anything else that pins the CA bundle.

This module provides OpenBolt plans for that lifecycle:

- `openvox_ca::check`: report the expiry of the CA bundle, the CRLs, the server's own certificate, and
  optionally every agent's certificate and CA copy. Read-only.
- `openvox_ca::extend`: re-sign the CA certificate in place on the CA host, handling both the
  single-certificate layout and the root plus intermediate bundle that `puppetserver ca setup` creates by
  default. Refuses externally issued CAs.
- `openvox_ca::distribute`: get the new bundle onto agents, either by uploading it over the transport or
  by removing each agent's copy so the next run fetches it.

The re-signing step itself is also proposed as a `puppetserver ca extend` subcommand in the OpenVox CA
tooling; see [openvoxserver-ca#56](https://github.com/OpenVoxProject/openvoxserver-ca/issues/56). When
that ships, the extend plan will prefer it and keep its own implementation as a fallback.

## Requirements

- OpenVox 8 or 9 on the CA host and on agents.
- OpenBolt on the machine you run the plans from.

## License

Apache-2.0. See [LICENSE](LICENSE).
