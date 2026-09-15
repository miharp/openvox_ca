# openvox_ca

Check, extend, and distribute the OpenVox CA certificate without reissuing agent certificates.

> **Warning:** This module rewrites the certificate authority's own certificate. A mistake here breaks
> authentication for the whole deployment. Back up the CA directory before you run anything that changes
> state, and try the procedure in a test environment first.

## Status

Early development. The `openvox_ca::check` and `openvox_ca::extend` plans work and have been exercised
against a three-node OpenVox 8 lab. The distribute plan described below is the intended interface and
will appear as the work progresses.

The module is not on the Forge. To try a release, pin a git tag in your Puppetfile:

```ruby
mod 'openvox_ca',
  git: 'https://github.com/miharp/openvox_ca.git',
  ref: 'v0.2.0'
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

### Extend the CA certificate

Re-sign the CA certificate in place on the CA host, with a new fifteen-year lifetime:

```console
bolt plan run openvox_ca::extend ca=puppet.example.com dry_run=true
bolt plan run openvox_ca::extend ca=puppet.example.com
```

The plan refuses to run when nothing on the CA is due to expire within `warn_days` (default 90)
unless you pass `force=true`, and it refuses an externally issued CA, meaning one whose private key
is not on the CA host. Otherwise it:

1. stops `puppetserver`;
2. re-signs every certificate in the CA bundle with the same key, subject, serial, and extensions,
   handling both the single self-signed layout and the root plus intermediate bundle;
3. re-signs any CRL whose `next_update` has passed (`crls=all` re-signs every CRL, `crls=none` leaves
   them alone), keeping the revoked entries and incrementing `crlNumber`;
4. writes the new bundle and CRLs to the CA directory and to the server's own SSL directory, after
   backing each file up as `<file>.<timestamp>.bak` beside the original;
5. refreshes OpenVoxDB's copies with `puppetdb ssl-setup -f` and restarts it, when it runs on the CA
   host (`restart_puppetdb=false` to skip);
6. starts `puppetserver`, waits for it to answer, and reports the expiry before and after.

Pass `ttl=<duration>` to choose a different lifetime, in the same format the CA gem accepts (`15y`,
`400d`, `24h`). Pass `regen_primary_cert=true` when the server's own certificate has also expired:
the plan then replaces it with one generated offline by `puppetserver ca generate --ca-client`, which
is the only way to get the `pp_cli_auth` extension the CA CLI depends on. Alt names are not carried
over automatically, so pass `dns_alt_names='["puppet","puppet.example.com"]'`; the plan prints the
old certificate's names so you can compare.

Agents keep working with their old copy of the CA certificate for as long as it is valid, because
the signing key has not changed. OpenVox agents also refresh their copy of the CA bundle from the
server once a day by default (`ca_refresh_interval`), so on a healthy deployment the new
certificate reaches every agent within a day without any further action. Distributing it by hand is
only needed when the old certificate has already expired, or sooner than a day is required.

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
