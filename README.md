# openvox_ca

Check, extend, and distribute the OpenVox CA certificate without reissuing agent certificates.

> **Warning:** This module rewrites the certificate authority's own certificate. A mistake here breaks
> authentication for the whole deployment. Back up the CA directory before you run anything that changes
> state, and try the procedure in a test environment first.

## Status

Early development. The `openvox_ca::check`, `openvox_ca::extend`, and `openvox_ca::distribute` plans work
and have been exercised against a three-node lab on OpenVox 8 and on OpenVox 9.0.0-rc1, and in Beaker
acceptance tests on OpenVox 8.

The module is not on the Forge. To try a release, pin a git tag in your Puppetfile:

```ruby
mod 'openvox_ca',
  git: 'https://github.com/miharp/openvox_ca.git',
  ref: 'v0.4.2'
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
expired  puppet.example.com           issued_cert    2026-08-30    -17  /CN=old-build.example.com
warn     puppet.example.com           issued_cert    2026-11-02     47  /CN=agent07.example.com (revoked)
ok       puppet.example.com           ca_cert        2031-09-12   1823  /CN=Puppet CA: puppet.example.com
ok       puppet.example.com           crl            2031-09-12   1823  /CN=Puppet CA: puppet.example.com
ok       agent01.example.com          host_cert      2031-09-12   1823  /CN=agent01.example.com
ok       agent01.example.com          local_ca_copy  2031-09-12   1823  /CN=Puppet CA: puppet.example.com
Issued certificates on puppet.example.com: 212 total, 1 due within 90 days, 1 expired, 3 revoked
```

The CA check also audits every certificate the CA has issued, read from the CA's signed directory,
so the whole fleet's expiry is visible from the CA host without an inventory. By default only the
issued certificates that are due within `warn_days` or already expired are listed, one row each with
kind `issued_cert`, and the summary line counts the whole directory. Pass `issued=all` to list every
one, or `issued=none` to skip the directory. A certificate that is still in the signed directory but
listed in the CA's CRL is marked `(revoked)`. Issued certificates never change the CA's own status,
because an expiring agent certificate is not a reason to extend the CA; it is a reason to renew
that agent's certificate.

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
   them alone), keeping the revoked entries and incrementing `crlNumber`. OpenVox Server also renews
   its own CRL whenever it is within 30 days of expiry, so this step usually finds nothing to do;
4. writes the new bundle and CRLs to the CA directory and to the server's own SSL directory, after
   backing each file up as `<file>.<timestamp>.bak` beside the original (`<file>.<timestamp>-N.bak`
   when that name is already taken, so no backup is ever overwritten);
5. refreshes OpenVoxDB's copies with `puppetdb ssl-setup -f` and restarts it, when it runs on the CA
   host (`restart_puppetdb=false` to skip);
6. starts `puppetserver`, waits for it to answer, and reports the expiry before and after.

If any step between the stop and the start fails, the plan starts `puppetserver` again before it
fails, so a refusal or a broken step never leaves the deployment down. A failed server certificate
regeneration puts the old certificate and key back.

The re-signing in step 2 is done by `puppetserver ca extend` when the CA CLI on the host has that
subcommand, which is proposed in
[openvoxserver-ca#56](https://github.com/OpenVoxProject/openvoxserver-ca/issues/56) and not yet
released, and by the module's own implementation otherwise. The task probes for the subcommand
by looking for an `extend` action in `puppetserver ca --help`, takes its own backups before calling it, and checks afterwards
that every certificate kept its serial and key and moved its expiry. Pass `implementation=library`
to never use the subcommand, or `implementation=gem` to insist on it. Until the subcommand ships,
the gem path has only been exercised against a stand-in in the unit tests.

Pass `ttl=<duration>` to choose a different lifetime, in the same format the CA gem accepts (`15y`,
`400d`, `24h`). Pass `regen_primary_cert=true` when the server's own certificate has also expired:
the plan then replaces it with one generated offline by `puppetserver ca generate --ca-client`, which
is the only way to get the `pp_cli_auth` extension the CA CLI depends on. Alt names are not carried
over automatically, so pass `dns_alt_names='["puppet","puppet.example.com"]'`; the plan prints the
old certificate's names so you can compare.

Agents keep working with their old copy of the CA certificate for as long as it is valid, because
the signing key has not changed and each agent validates the server against its own copy, not
against the certificate the server holds. The reverse is also true: an expired CA on the server
only breaks an agent once that agent's copy has expired, which in practice is the same moment,
since every copy is the same certificate. OpenVox agents also refresh their copy of the CA bundle from the
server once a day by default (`ca_refresh_interval`), so on a healthy deployment the new
certificate reaches every agent within a day without any further action. Distributing it by hand is
only needed when the old certificate has already expired, or sooner than a day is required.

### Distribute the new bundle to agents

Usually unnecessary: OpenVox agents refresh their copy of the CA bundle from the server every
`ca_refresh_interval` (one day by default), so after an extend the new certificate reaches every
healthy agent within a day. Use this plan when the agents' old copy has already expired, or when a
day is too long to wait.

```console
bolt plan run openvox_ca::distribute ca=puppet.example.com targets=agents
bolt plan run openvox_ca::distribute ca=puppet.example.com targets=agents strategy=upload
```

`refetch`, the default, moves each agent's `ca.pem` and `crl.pem` aside and runs the agent once in
no-op mode. An agent with no CA bundle fetches one from the server without needing a valid one, so
this works even after the old copy has expired. `upload` reads the bundle and CRL from the CA host
and writes them to each target directly, then restarts the agent service (`restart_agent=false` to
skip); use it for hosts that cannot reach the server or should not run the agent. Both strategies
back the old files up beside the originals and finish by printing each host's new CA expiry.

The CA report also says which layout the bundle has (`single`, or `intermediate` for the root plus
signing certificate pair) and lists any CA certificate whose private key is not on disk, which
means the CA was issued externally and cannot be extended here.

### Manage the agents' copy from a manifest instead

Before the old certificate expires, agents can still talk to the server, so the simplest way to put
the new bundle on every agent sooner than `ca_refresh_interval` is a `file` resource in a profile
that every agent applies. The content comes from the compiling server's own copy, so compilers
must already hold the new bundle, which the extend plan does not do for separate compilers.

```puppet
# profile::ca_bundle: keep the agent's CA bundle in step with the server's.
$localcacert = $facts['os']['family'] ? {
  'windows' => 'C:/ProgramData/PuppetLabs/puppet/etc/ssl/certs/ca.pem',
  default   => '/etc/puppetlabs/puppet/ssl/certs/ca.pem',
}

file { $localcacert:
  ensure  => file,
  content => file($settings::localcacert),
}
```

This does not work once the old certificate has expired, because the agent can no longer fetch a
catalog; use the distribute plan then. It also does nothing for hosts that pin the bundle outside
the agent's SSL directory, such as an OpenVoxDB on its own host.

## How it works

An OpenVox CA certificate created by `puppetserver ca setup` is valid for 15 years. A CA the server
generated on its own first start uses `ca_ttl` instead, which is five years by default, and has
the single-certificate layout. Either way, when it expires every TLS connection in the deployment
fails at once. Rebuilding the CA is not necessary: re-signing the existing CA certificate with the
same key and subject gives it a new validity period, and every host certificate the CA ever issued
stays valid because the signing key has not changed. Only the CA certificate file changes, and the
new copy then has to reach agents and anything else that pins the CA bundle.

This module provides OpenBolt plans for that lifecycle:

- `openvox_ca::check`: report the expiry of the CA bundle, the CRLs, the server's own certificate,
  every certificate the CA has issued, and optionally every agent's certificate and CA copy.
  Read-only.
- `openvox_ca::extend`: re-sign the CA certificate in place on the CA host, handling both the
  single-certificate layout and the root plus intermediate bundle that `puppetserver ca setup` creates by
  default. Refuses externally issued CAs.
- `openvox_ca::distribute`: get the new bundle onto agents, either by uploading it over the transport or
  by removing each agent's copy so the next run fetches it.

The re-signing step itself is also proposed as a `puppetserver ca extend` subcommand in the OpenVox CA
tooling; see [openvoxserver-ca#56](https://github.com/OpenVoxProject/openvoxserver-ca/issues/56). The
extend task already prefers that subcommand when it finds one and keeps its own implementation as the
fallback. See [REFERENCE.md](REFERENCE.md) for every plan and task parameter.

## Testing against a lab

`contrib/lab_battery.sh` runs 31 positive and negative cases against a disposable lab from the CA
host: the guards and refusals, both extend layouts of behaviour, both distribute strategies, a full
expire-and-recover cycle, and a rollback from the backups. It rewrites the CA certificate and
restarts every service, so never point it at a real deployment. See the header of the script for
the variables it takes.

## Development

Changes reach `main` through pull requests only. A ruleset on `main` requires a pull request, the
`Puppet / Test suite` check from CI (which gates the static checks, the unit suite, and the Beaker
acceptance jobs), signed commits, and a merge commit, so the signed and DCO'd commits on the branch
stay as they are. Squash and rebase merges are disabled because GitHub's rebase merge drops commit
signatures. Release tags `v*` cannot be moved or deleted.

```console
git switch -c fix/something
git commit -S -s          # signed, with a Signed-off-by trailer
git push -u origin fix/something
gh pr create --fill
gh pr merge --auto --merge
```

Tests: `bundle exec rake spec` runs the unit specs for the Ruby libraries under `spec/unit` and the
plan specs under `spec/plans`, which run the plans through BoltSpec with every task and command
stubbed to check the guards, the order of steps, the parameters passed on, and the recovery when a
step fails. `bundle exec rake beaker` runs the Beaker acceptance spec on an amd64 host with Docker.

A release is a version bump and changelog entry merged the same way, followed by a signed tag on
`main`: `git tag -s vX.Y.Z && git push origin vX.Y.Z`. The tag push builds the tarball and attaches
it to a GitHub release. Run the lab battery before tagging anything that touches a plan or task.

## Requirements

- OpenVox 8 or 9 on the CA host and on agents.
- OpenBolt on the machine you run the plans from.

## License

Apache-2.0. See [LICENSE](LICENSE).
