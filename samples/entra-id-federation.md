# Set up Entra ID (Azure AD) federation for Safeguard

This walkthrough shows how to use **safeguard-ps** to configure Microsoft Entra ID
(Azure AD) as a SAML external federation identity provider for Safeguard for
Privileged Passwords (SPP), create a federated user, and enable passwordless /
passkey (FIDO2) sign-in.

The companion script is [`entra-id-federation-setup.ps1`](entra-id-federation-setup.ps1).

## Prerequisites

- The safeguard-ps module installed (`Import-Module safeguard-ps`).
- Network access to your SPP appliance and permission to administer identity
  providers and users (e.g. a User Admin / appliance admin).
- Permission in Entra ID to create an Enterprise Application.

## Steps

### 1. Get SPP's SAML service provider (SP) metadata

Entra ID needs SPP's SP **EntityId** (Identifier) and **Assertion Consumer
Service** (ACS / Reply) URL. `Get-SafeguardSamlMetadata` reads SPP's published SP
metadata (no login required) and can write the raw XML to a file to upload to Entra.

```powershell
# Inspect the key SP properties
Get-SafeguardSamlMetadata spp.example.com -Insecure |
    Select-Object EntityId, AssertionConsumerServices

# Write the SP metadata XML to a file to upload to Entra
Get-SafeguardSamlMetadata spp.example.com -Insecure -OutFile .\SafeguardSpMetadata.xml
```

### 2. Create the Enterprise Application in Entra ID

In the Entra ID portal (this part is manual):

1. **Enterprise applications** -> **New application** -> **Create your own application**.
2. Open **Single sign-on (SAML)** -> **Upload metadata file** and select the
   `SafeguardSpMetadata.xml` from Step 1. This fills in the **Identifier (Entity ID)**
   and **Reply URL (ACS)** for SPP.
3. **Assign** the users who should be able to sign in to Safeguard.
4. Copy the **App Federation Metadata Url** from the SAML signing certificate
   section. You will pass this to SPP in Step 3.

### 3. Create the external federation provider in SPP

`-Realm` is the email-domain suffix SPP matches against a login name to route
users to this provider. `-MetadataUrl` is the Entra app's federation metadata URL
from Step 2. (Safeguard requires `Realm`.)

```powershell
Connect-Safeguard spp.example.com -Insecure

New-SafeguardExternalFederationIdentityProvider "Entra ID" `
    -Realm example.com `
    -MetadataUrl "https://login.microsoftonline.com/<tenant-id>/federationmetadata/2007-06/federationmetadata.xml?appid=<app-id>" `
    -Description "Entra ID federation"
```

You can manage the provider afterward with
`Get-`, `Edit-`, `Remove-`, and `Sync-SafeguardExternalFederationIdentityProvider`.

### 4. Create a federated user

For external federation, `-Identity` must match the **name claim** the STS returns
for the user (typically their email address).

```powershell
New-SafeguardUser "Entra ID" jsmith -Identity jsmith@example.com -FirstName John -LastName Smith
```

## Enabling passkey login (Entra ID AADSTS75011)

By default SPP's SAML SP asks the external STS for the
`Password, ProtectedTransport` authentication context. When a user signs in to
Entra ID with a **passkey / FIDO2 / passwordless** method, Entra returns the
`MultiFactor, Fido` context instead, which does not match what SPP requested, and
the sign-in fails with:

```
AADSTS75011: Authentication method 'MultiFactor, Fido' by which the user
authenticated with the service doesn't match requested authentication method
'Password, ProtectedTransport'.
```

To allow passwordless sign-in, relax the requested context to `unspecified` so
SPP accepts any authentication method:

```powershell
Edit-SafeguardExternalFederationIdentityProvider "Entra ID" `
    -AuthnContextClasses "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
```

Verify the setting:

```powershell
(Get-SafeguardExternalFederationIdentityProvider "Entra ID").ExternalFederationProperties |
    Select-Object AuthnContextClasses, AuthnContextComparison
```

Passkey / FIDO2 / passwordless sign-in should now succeed.

## Running the script

The script performs Steps 1-4. Because creating the Entra app (Step 2) is manual,
run it once to produce the SP metadata file, create the Entra app, then run it
again with `-MetadataUrl` to finish:

```powershell
# First pass: writes the SP metadata XML, prints the Entra portal instructions
.\entra-id-federation-setup.ps1 -Appliance spp.example.com -ProviderName "Entra ID" -Realm example.com

# After creating the Entra Enterprise Application, finish provider + user creation
.\entra-id-federation-setup.ps1 -Appliance spp.example.com -ProviderName "Entra ID" -Realm example.com `
    -MetadataUrl "https://login.microsoftonline.com/<tenant-id>/federationmetadata/2007-06/federationmetadata.xml?appid=<app-id>" `
    -UserName jsmith -UserIdentity jsmith@example.com
```

The script prints the exact `Edit-SafeguardExternalFederationIdentityProvider`
command to enable passkey login as a final, separate step.
