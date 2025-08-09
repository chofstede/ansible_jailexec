# Integration Tests

This directory contains integration tests for the Ansible jailexec connection plugin that run against a real FreeBSD jail.

## GitHub Secrets Setup

To run the integration tests in GitHub Actions, you need to configure the following secrets in your repository:

### Required Secrets

1. **FREEBSD_HOST**: The IPv6 address or hostname of your FreeBSD server
   - Example: `2a13:e3c1:400e:1337::672`

2. **FREEBSD_USER**: The SSH username for connecting to the FreeBSD host
   - Example: `ansible`
   - This user needs sudo privileges to execute `jexec` commands

3. **FREEBSD_SSH_KEY**: The private SSH key for authentication
   - Generate with: `ssh-keygen -t ed25519 -C "ansible-ci"`
   - Add the public key to `~/.ssh/authorized_keys` on the FreeBSD host
   - Copy the entire private key content including headers

4. **FREEBSD_HOST_KEY**: The SSH host key of your FreeBSD server
   - Get it with: `ssh-keyscan -t ed25519 2a13:e3c1:400e:1337::672`
   - This prevents SSH host verification issues

## Setting up GitHub Secrets

1. Go to your repository on GitHub
2. Navigate to Settings → Secrets and variables → Actions
3. Click "New repository secret" for each secret
4. Enter the secret name and value

## Local Testing

To run the tests locally:

1. Copy the example inventory:
   ```bash
   cp test-inventory.ini.example test-inventory.ini
   ```

2. Edit `test-inventory.ini` with your FreeBSD server details

3. Run the smoke tests:
   ```bash
   ansible-playbook -i test-inventory.ini smoke-test.yml -v
   ```

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