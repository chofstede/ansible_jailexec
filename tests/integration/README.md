# Integration Tests

This directory contains integration tests for the Ansible jailexec connection plugin that run against a real FreeBSD jail.

## GitHub Secrets Setup

To run the integration tests in GitHub Actions, you need to configure the following secrets in your repository:

### Required Secrets

1. **FREEBSD_HOST**: The IPv6 address or hostname of your FreeBSD server
   - Example: `2001:db8::10`

2. **FREEBSD_USER**: The SSH username for connecting to the FreeBSD host
   - Example: `ansible`
   - This user needs sudo privileges to execute `jexec` commands

3. **FREEBSD_SSH_KEY**: The private SSH key for authentication
   - Generate with: `ssh-keygen -t ed25519 -C "ansible-ci"`
   - Add the public key to `~/.ssh/authorized_keys` on the FreeBSD host
   - Copy the entire private key content including headers

4. **FREEBSD_HOST_KEY**: The SSH host key of your FreeBSD server
   - Get it with: `ssh-keyscan -t ed25519 2001:db8::10`
   - This prevents SSH host verification issues

## Setting up GitHub Secrets

1. Go to your repository on GitHub
2. Navigate to Settings -> Secrets and variables -> Actions
3. Click "New repository secret" for each secret
4. Enter the secret name and value

## Building throwaway test jails

On a FreeBSD 15 host installed from pkgbase, three serviceless jails are enough
to cover every code path, and cost about 400 MB each:

```sh
# Host tooling (a minimal pkgbase install ships neither).
pkg install -y FreeBSD-jail doas

# Jail root from the base repo. pkg resolves the repo fingerprints *inside*
# the rootdir, so the keys have to be copied in first, or the install fails
# with "Error opening the trusted directory /usr/share/keys/pkgbase-15/trusted".
mkdir -p /jails/smokeroot/usr/share/keys
cp -R /usr/share/keys/ /jails/smokeroot/usr/share/keys/
pkg --rootdir /jails/smokeroot install -r FreeBSD-base -y FreeBSD-runtime
pkg --rootdir /jails/smokeroot install -y python3

# pkg --rootdir does not run ldconfig inside the jail, so the interpreter
# would fail with: Shared object "libpython3.12.so.1.0" not found.
jail -c smokeroot && jexec smokeroot /sbin/ldconfig -m /usr/local/lib
```

`/etc/jail.conf` needs no `exec.start` — the jails run no services at all,
which is all `jexec` requires. `mount.devfs` *is* required, because Python
wants `/dev/urandom`:

```
exec.clean;
mount.devfs;
persist;
path = "/jails/$name";
host.hostname = "$name";

smokeroot { }
smokeuser { }
smokealias { }
```

Useful jail variations for covering the plugin's behaviour:

- **`smokeroot`** — baseline, `ansible_jail_user=root`.
- **`smokeuser`** — add an in-jail user (`pw -R /jails/smokeuser useradd -n tester -m -s /bin/sh`)
  so `ansible_jail_user=tester` exercises `jexec -U` against the *jail's* passwd database.
- **`smokealias`** — reach it under a different inventory hostname via
  `ansible_jail_name`, with `ansible_host` set to an unroutable TEST-NET address
  (`192.0.2.99`). The plugin must SSH to `ansible_jail_host` and `jexec` the
  jail name, never `ansible_host`.

Set `ansible_remote_tmp=/tmp/.ansible-tmp` for these hosts: Ansible otherwise
builds its temp path from the SSH user's home, which does not exist inside the
jail.

## Local Testing

To run the tests locally:

1. Copy the example inventory:
   ```bash
   cp test-inventory.ini.example test-inventory.ini
   ```

2. Edit `test-inventory.ini` with your FreeBSD server details. Note:
   - The inventory hostname is the **jail name** (override with `ansible_jail_name`).
   - `ansible_jail_host` is **required**; it is the FreeBSD host running the jail.
   - The SSH user needs a passwordless `doas` (or `sudo`) rule for `jexec` on the
     host, e.g. `permit nopass ansible as root cmd jexec`, or set
     `ansible_jail_privilege_escalation=none` if you SSH in as root.

3. Run the smoke tests:
   ```bash
   ansible-playbook -i test-inventory.ini smoke-test.yml -v
   ```

If a task fails with `Failed to create temporary directory`, the `jexec`
wrapper itself is failing on the host. Re-run with `-vvvv` to see the stderr,
or reproduce it manually:

```bash
ssh <user>@<jail-host> 'doas jexec <jail-name> /bin/sh -c id'
```

Typical causes: the jail isn't running or is named differently (`jls` on the
host shows the real names), the `doas`/`sudo` rule for `jexec` is missing, or
`doas` prompts for a password (use `permit nopass`).

## Test Coverage

The smoke tests verify:
- Basic connectivity using ansible.builtin.ping
- Command execution (hostname, uname)
- File operations (create, verify, delete)
- Working directory changes
- Python interpreter availability

## Security Considerations

- Use a dedicated test jail for CI/CD to avoid affecting production systems
- Limit the SSH user's sudo permissions to only necessary commands
- Consider using a separate SSH key specifically for CI/CD
- Regularly rotate credentials
- Use IPv6 firewall rules to restrict access to the test server

## IPv6 Connectivity

**Important**: GitHub-hosted runners do not support IPv6 connectivity. If your FreeBSD host only has an IPv6 address, you have these options:

1. **Use a self-hosted runner** with IPv6 support
2. **Configure IPv4 access** to your FreeBSD host (dual-stack)
3. **Set up a jump host** with both IPv4 and IPv6 connectivity
4. **Run tests locally** instead of in CI

The workflow will gracefully handle the lack of connectivity and provide appropriate warnings.

## Troubleshooting

If tests fail:
1. Verify SSH connectivity: `ssh user@host`
2. Check jail is running: `jls` on the FreeBSD host
3. Ensure Python is installed in the jail
4. Review GitHub Actions logs for detailed error messages
5. For IPv6 hosts, ensure you're using a runner with IPv6 support