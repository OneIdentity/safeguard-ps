# Samples Using safeguard-ps
Sample scripts based on safeguard-ps.  These scripts are meant
to give ideas about how safeguard-ps may be used to solve
problems.

## Sample Scripts

- **certificate-user-demo.ps1**

  This script demonstrates how to configure certificates in Safeguard so that you can authenticate
  to the API using a certificate user.

- **new-test-entitlement.ps1**

  This script creates an approver group, requester group, and an entitlement with the given name.
  The entitlement will have a Password, an SSH, and an RDP access policy in it.  The Password
  access policy will be auto-approved.  You just need to fill out the scopes and group memberships.

- **fix-service-account-ssh-keys.ps1**

  A sample script posted to correct specific problem that occurred in the Safeguard 2.2 upgrade.