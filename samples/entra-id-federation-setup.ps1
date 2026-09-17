# Copyright (c) 2026 One Identity LLC. All rights reserved.
#
# Walkthrough: configure Microsoft Entra ID (Azure AD) as a SAML external
# federation identity provider for Safeguard for Privileged Passwords (SPP),
# then create a federated user.
#
# The steps mirror what you do by hand:
#   1. Use safeguard-ps to get SPP's SAML service provider (SP) metadata.
#   2. Upload that metadata to Entra ID to create a new Enterprise Application,
#      then copy the app's federation metadata URL (manual, in the Entra portal).
#   3. Create the external federation identity provider in SPP.
#   4. Create a Safeguard user backed by that provider.
#
# Enabling passkey / passwordless (FIDO2) sign-in is a separate step -- see
# "Enabling passkey login" at the bottom of this script and the README.
#
# NOTE on -Insecure: the -Insecure switch disables Safeguard appliance SSL
# certificate verification. This sample uses it because development / lab
# appliances typically present self-signed certificates. For production
# scripts, install a trusted certificate on the appliance and OMIT -Insecure.

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$Appliance,
    [Parameter(Mandatory=$true)]
    [string]$ProviderName,
    [Parameter(Mandatory=$true)]
    [string]$Realm,
    # The Entra ID app's federation metadata URL. You get this in Step 2 after
    # creating the Enterprise Application from SPP's SP metadata. Run this script
    # once to produce the SP metadata file (Step 1), create the app in Entra,
    # then run it again with -MetadataUrl to finish Steps 3 and 4.
    [Parameter(Mandatory=$false)]
    [string]$MetadataUrl,
    [Parameter(Mandatory=$false)]
    [string]$UserName,
    [Parameter(Mandatory=$false)]
    [string]$UserIdentity
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

# Connect interactively -- prompts for identity provider, user name, and password.
# Substitute your own -AccessToken / connection handling as needed.
Write-Host -ForegroundColor Yellow "Connecting to $Appliance ..."
$AccessToken = (Connect-Safeguard -Appliance $Appliance -Insecure -NoSessionVariable)
$Common = @{ Appliance = $Appliance; AccessToken = $AccessToken; Insecure = $true }

try
{
    # -------------------------------------------------------------------------
    # Step 1: Get SPP's SAML service provider (SP) metadata.
    #
    # Entra ID needs SPP's SP EntityId (Identifier) and Assertion Consumer
    # Service (ACS / Reply) URL. Get-SafeguardSamlMetadata reads the appliance's
    # published SP metadata anonymously; -OutFile writes the raw XML you upload
    # to Entra.
    # -------------------------------------------------------------------------
    Write-Host -ForegroundColor Yellow "`nStep 1: Getting SPP SAML service provider metadata"
    $Sp = (Get-SafeguardSamlMetadata $Appliance -Insecure)
    $MetadataFile = (Get-SafeguardSamlMetadata $Appliance -Insecure -OutFile ".\$($Appliance)-SafeguardSpMetadata.xml")
    Write-Host ("    SP EntityId (Identifier)   : {0}" -f $Sp.EntityId)
    Write-Host ("    Assertion Consumer Service : {0}" -f (($Sp.AssertionConsumerServices | ForEach-Object { $_.Location }) -join ", "))
    Write-Host ("    SP metadata XML written to : {0}" -f $MetadataFile.FullName)

    # -------------------------------------------------------------------------
    # Step 2: Create the Enterprise Application in Entra ID (manual).
    # -------------------------------------------------------------------------
    Write-Host -ForegroundColor Cyan @"

    Step 2: In the Entra ID portal (one time, cannot be automated from here):
      1. Enterprise applications -> New application -> Create your own application.
      2. Set up Single sign-on (SAML) and Upload metadata file -- select the SP
         metadata XML written above. This fills in the Identifier (Entity ID) and
         Reply URL (ACS) for SPP.
      3. Assign the users who should be able to sign in to Safeguard.
      4. Copy the App Federation Metadata Url from the SAML signing section and
         re-run this script with:  -MetadataUrl <that url>
"@

    if (-not $MetadataUrl)
    {
        Write-Host -ForegroundColor Yellow "`nNo -MetadataUrl supplied. Stopping after Step 1/2. Create the Entra app, then re-run with -MetadataUrl to finish."
        return
    }

    # -------------------------------------------------------------------------
    # Step 3: Create the external federation identity provider in SPP, pointing
    # at the Entra ID federation metadata. Realm is the email-domain suffix SPP
    # matches against a login name to route users to this provider.
    # -------------------------------------------------------------------------
    Write-Host -ForegroundColor Yellow "`nStep 3: Creating external federation identity provider '$ProviderName' (realm '$Realm')"
    $Idp = (New-SafeguardExternalFederationIdentityProvider @Common $ProviderName -Realm $Realm -MetadataUrl $MetadataUrl `
                -Description "Entra ID federation created by entra-id-federation-setup.ps1")
    Write-Host ("    Created provider Id {0} ({1})" -f $Idp.Id, $Idp.Name)

    # -------------------------------------------------------------------------
    # Step 4: Create a Safeguard user backed by this provider. For external
    # federation, -Identity must match the name claim the STS returns for the
    # user (typically their email address).
    # -------------------------------------------------------------------------
    if ($UserName)
    {
        if (-not $UserIdentity) { $UserIdentity = $UserName }
        Write-Host -ForegroundColor Yellow "`nStep 4: Creating federated user '$UserName' (identity '$UserIdentity')"
        $User = (New-SafeguardUser @Common $ProviderName $UserName -Identity $UserIdentity)
        Write-Host ("    Created user Id {0} ({1})" -f $User.Id, $User.Name)
    }
    else
    {
        Write-Host -ForegroundColor Yellow "`nStep 4: Skipped (no -UserName). Create users later with:"
        Write-Host        "          New-SafeguardUser '$ProviderName' <username> -Identity <name-claim-email>"
    }

    # -------------------------------------------------------------------------
    # Enabling passkey login (separate step -- ADO Bug 737561 / AADSTS75011).
    #
    # By default SPP asks the STS for the "Password, ProtectedTransport"
    # authentication context. A passkey / FIDO2 / passwordless sign-in returns
    # "MultiFactor, Fido" instead, so Entra rejects it:
    #
    #   AADSTS75011: Authentication method 'MultiFactor, Fido' ... doesn't match
    #   requested authentication method 'Password, ProtectedTransport'.
    #
    # To allow passwordless sign-in, relax the requested context to unspecified:
    # -------------------------------------------------------------------------
    Write-Host -ForegroundColor Cyan @"

    Enabling passkey login (run this to allow passwordless / FIDO2 sign-in):

      Edit-SafeguardExternalFederationIdentityProvider '$ProviderName' ``
          -AuthnContextClasses 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified'
"@

    Write-Host -ForegroundColor Green "`nDone. Sign in from the Safeguard login page by choosing '$ProviderName'."
}
finally
{
    Disconnect-Safeguard -Appliance $Appliance -AccessToken $AccessToken -Insecure -ErrorAction SilentlyContinue
}
