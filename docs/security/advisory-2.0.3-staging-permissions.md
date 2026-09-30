# Security Advisory: staged `put_file` payloads readable by other host users (fixed in 2.0.3)

| | |
|---|---|
| **Affected** | `ansible-jailexec` (the `jailexec` connection plugin), all releases `<= 2.0.2` |
| **Fixed in** | `2.0.3` |
| **Severity** | Medium |
| **CWE** | CWE-378 (Creation of Temporary File With Insecure Permissions) |
| **Vector (CVSS 3.1)** | `AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` (4.7) |
| **GHSA** | GHSA-cfm5-946c-m3qx |
| **CVE** | pending |

## Summary

`put_file` moves a file into a jail in two steps: it uploads the file to the **jail
host** under a random name, `/tmp/ansible-jailexec-<hex>`, and then writes it into the
jail with `jexec <jail> /bin/sh -c 'cat > <dest>' < <staged>`.

The staged file was created directly in `/tmp` with no permission restriction. SFTP
and SCP create an uploaded file with the **source file's mode**, masked by the jail
host's umask. With the common umask `022`, a source file with mode `0644` was staged as
`0644`, so any local account on the jail host could read it until the in-jail write
finished and the staged file was removed. `fetch_file` already staged its copy with
`umask 077`; `put_file` did not.

## Impact

A local, unprivileged account on the **jail host** that is not the SSH user used by
Ansible (a monitoring or backup service account, another administrator, a co-tenant)
can read the contents of files pushed into any jail managed by the plugin. Watching
`/tmp` with kqueue or a polling loop is enough to catch the file reliably; the window
lasts for the whole upload plus the in-jail write.

Exposure depends on how the file reaches `put_file`:

- **Exposed:** files transferred with their on-disk mode, chiefly `copy src=` (also
  `unarchive`, `script`) with a plaintext source file that is group- or
  world-readable on the controller, e.g. a TLS key or credentials file kept
  unencrypted in a repository.
- **Not exposed with SFTP or SCP:** files Ansible creates itself as `0600` temporary
  files on the controller: AnsiballZ module payloads (including module arguments),
  `template` output, `copy content=`, and Vault-encrypted sources, which Ansible
  decrypts to a `0600` file first.

Processes **inside** a jail cannot see the host's `/tmp` (unless it is mounted into the
jail) and are not able to exploit this. Root on the host can read the files regardless.

Preconditions:
- A second, non-root local account on the jail host.
- A playbook transfers a sensitive file whose source mode is group- or world-readable.

## The fix (2.0.3)

Every transfer now stages inside a private per-transfer directory:

```
umask 077 && mkdir /tmp/ansible-jailexec-<hex>          # mode 0700; fails if the name exists
<upload> -> /tmp/ansible-jailexec-<hex>/payload
jexec <jail> /bin/sh -c 'mkdir -p <dir> && cat > <dest>' < .../payload && rm -rf /tmp/ansible-jailexec-<hex>
```

Other host users cannot reach the payload inside a `0700` directory, whatever mode the
upload is created with and whichever `ssh_transfer_method` is used. `mkdir` refuses a
pre-existing name, so the directory cannot be pre-planted. The directory is removed on
success and on every failure path. `fetch_file` uses the same directory.

The fix was verified against FreeBSD 15.1 jails: with 2.0.2, an observer running as
`nobody` read the staged payload of every `copy` task; with 2.0.3, the same observer
only saw `drwx------` directories and read nothing.

## Workarounds

If you cannot upgrade right away:

- Make the SFTP server create files privately on the jail host:
  `Subsystem sftp /usr/libexec/sftp-server -u 077` in `sshd_config` (or a `umask=077`
  entry for the Ansible SSH user's login class in `login.conf`). Setting `umask` in a
  shell startup file is **not** sufficient, because `sftp-server` runs non-interactively.
- Keep secret source files `0600` on the controller, or store them encrypted with
  Ansible Vault.
- Make sure no untrusted local accounts exist on jail hosts.

## Remediation

Upgrade to `ansible-jailexec >= 2.0.3`. No inventory changes are required.

## Credit

Reported by zx (GitHub: @manus-pi).

## Timeline

- 2026-09-30: Report received; confirmed and reproduced against FreeBSD 15.1 jails;
  fix developed.
- 2026-10-01: 2.0.3 released and advisory published.
