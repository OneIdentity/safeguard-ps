<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
# Helpers
Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local

# Well-known SAML authentication context class that tells the external STS to
# accept any authentication method. Setting an external federation provider to
# this value resolves Entra ID error AADSTS75011, which occurs when a user
# authenticates passwordless (Windows Hello / passkey / FIDO2) but Safeguard's
# default request only accepts Password / PasswordProtectedTransport.
$script:UnspecifiedAuthnContextClass = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"

function Resolve-SafeguardExternalFederationIdentityProviderId
{
    [CmdletBinding()]
    [OutputType([int])]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Provider
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Provider.Id -as [int])
    {
        $Provider = $Provider.Id
    }

    if ($Provider -as [int])
    {
        # Verify the ID actually refers to an external federation provider
        $local:Idp = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "IdentityProviders/$($Provider -as [int])")
        if ($local:Idp.TypeReferenceName -ne "ExternalFederation")
        {
            throw "Identity provider '$Provider' is of type '$($local:Idp.TypeReferenceName)', not ExternalFederation"
        }
        $local:Idp.Id
    }
    else
    {
        $local:EscapedName = $Provider -replace "'", "\'"
        $local:Idps = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "IdentityProviders" `
                            -Parameters @{ filter = "Name ieq '$($local:EscapedName)'" })
        # Constrain client-side to external federation to be robust across appliance versions
        $local:Idps = @($local:Idps | Where-Object { $_.TypeReferenceName -eq "ExternalFederation" })
        if (-not $local:Idps)
        {
            throw "Unable to find external federation identity provider matching '$Provider'"
        }
        if ($local:Idps.Count -ne 1)
        {
            throw "Found $($local:Idps.Count) external federation identity providers matching '$Provider'"
        }
        $local:Idps[0].Id
    }
}

<#
.SYNOPSIS
Get external federation identity providers configured in Safeguard via the Web API.

.DESCRIPTION
Get the SAML external federation identity providers that have been configured in
Safeguard.  These are used to authenticate users against an external SAML 2.0
security token service such as Microsoft Entra ID.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ProviderToGet
An integer containing an ID or a string containing the name of the external
federation identity provider to return.

.PARAMETER Fields
An array of the identity provider property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardExternalFederationIdentityProvider

.EXAMPLE
Get-SafeguardExternalFederationIdentityProvider "Entra ID"
#>
function Get-SafeguardExternalFederationIdentityProvider
{
    [OutputType([object[]])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$ProviderToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = @{}
    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }

    if ($PSBoundParameters.ContainsKey("ProviderToGet"))
    {
        $local:Id = (Resolve-SafeguardExternalFederationIdentityProviderId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ProviderToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "IdentityProviders/$($local:Id)" `
            -Parameters $local:Parameters
    }
    else
    {
        $local:RemoveType = $Fields -and $Fields -notcontains "TypeReferenceName"
        if ($local:RemoveType)
        {
            # The type is needed for filtering even when it is not requested in the output.
            $local:Parameters["fields"] = (($Fields + "TypeReferenceName") -join ",")
        }
        # Server-side filter is not relied upon for the type; filter client-side for robustness
        $local:Idps = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "IdentityProviders" `
                            -Parameters $local:Parameters)
        $local:Idps | Where-Object { $_.TypeReferenceName -eq "ExternalFederation" } | ForEach-Object {
            if ($local:RemoveType) { $_.PSObject.Properties.Remove("TypeReferenceName") }
            $_
        }
    }
}

<#
.SYNOPSIS
Create a new SAML external federation identity provider in Safeguard via the Web API.

.DESCRIPTION
Create a new external federation identity provider that authenticates users
against an external SAML 2.0 security token service such as Microsoft Entra ID.
The provider is configured from the external STS's SAML metadata, supplied
either as an HTTPS URL that Safeguard monitors for changes, a local metadata
file, or a raw metadata XML string.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name for this external federation identity provider.

.PARAMETER Description
A string containing a description for this external federation identity provider.

.PARAMETER MetadataUrl
An HTTPS URL to the external STS SAML metadata.  Safeguard periodically monitors
this URL and downloads updates automatically.

.PARAMETER MetadataFile
A path to a local file containing the external STS SAML metadata XML.

.PARAMETER MetadataXml
A string containing the external STS SAML metadata XML.

.PARAMETER NameIdFormat
A string containing the SAML NameID format the external STS will return, for
example urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress.

.PARAMETER Realm
A string containing the realm (email domain suffix) used to route users to this
provider, for example secureidx.com.  This property is required by Safeguard.

.PARAMETER AuthnContextClasses
A string containing the SAML authentication context class(es) Safeguard will
request from the external STS.  Set this to
urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified to allow passwordless /
passkey / FIDO2 sign-in and resolve Entra ID error AADSTS75011.

.PARAMETER AuthnContextComparison
The comparison method used with AuthnContextClasses.  One of Exact, Minimum,
Maximum, or Better.

.PARAMETER RequireAuthentication
Whether the external STS must force re-authentication (SAML ForceAuthn).

.PARAMETER ApplicationIdOverride
A string overriding the application/entity ID Safeguard presents to the external STS.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardExternalFederationIdentityProvider "Entra ID" -Realm secureidx.com -MetadataUrl "https://login.microsoftonline.com/<tenant>/federationmetadata/2007-06/federationmetadata.xml?appid=<appid>"

.EXAMPLE
New-SafeguardExternalFederationIdentityProvider "Entra ID" -Realm secureidx.com -MetadataFile .\entra-metadata.xml -AuthnContextClasses "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
#>
function New-SafeguardExternalFederationIdentityProvider
{
    [CmdletBinding(DefaultParameterSetName="Url")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Url",Mandatory=$true)]
        [string]$MetadataUrl,
        [Parameter(ParameterSetName="File",Mandatory=$true)]
        [string]$MetadataFile,
        [Parameter(ParameterSetName="Xml",Mandatory=$true)]
        [string]$MetadataXml,
        [Parameter(Mandatory=$true)]
        [string]$Realm,
        [Parameter(Mandatory=$false)]
        [string]$NameIdFormat,
        [Parameter(Mandatory=$false)]
        [string]$AuthnContextClasses,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Exact","Minimum","Maximum","Better",IgnoreCase=$true)]
        [string]$AuthnContextComparison,
        [Parameter(Mandatory=$false)]
        [switch]$RequireAuthentication,
        [Parameter(Mandatory=$false)]
        [string]$ApplicationIdOverride
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($PSCmdlet.ParameterSetName)
    {
        "Url"  { $local:Metadata = $MetadataUrl }
        "File" {
            if (-not (Test-Path -LiteralPath $MetadataFile))
            {
                throw "Metadata file '$MetadataFile' does not exist"
            }
            $local:Metadata = (Get-Content -LiteralPath $MetadataFile -Raw)
        }
        "Xml"  { $local:Metadata = $MetadataXml }
    }

    $local:Fed = @{ FederationMetadata = $local:Metadata }
    if ($PSBoundParameters.ContainsKey("NameIdFormat")) { $local:Fed.NameIDFormat = $NameIdFormat }
    if ($PSBoundParameters.ContainsKey("Realm")) { $local:Fed.Realm = $Realm }
    if ($PSBoundParameters.ContainsKey("AuthnContextClasses")) { $local:Fed.AuthnContextClasses = $AuthnContextClasses }
    if ($PSBoundParameters.ContainsKey("AuthnContextComparison")) { $local:Fed.AuthnContextComparison = $AuthnContextComparison }
    if ($PSBoundParameters.ContainsKey("RequireAuthentication")) { $local:Fed.RequireAuthentication = [bool]$RequireAuthentication }
    if ($PSBoundParameters.ContainsKey("ApplicationIdOverride")) { $local:Fed.ApplicationIdOverride = $ApplicationIdOverride }

    $local:Body = @{
        TypeReferenceName = "ExternalFederation";
        Name = $Name;
        ExternalFederationProperties = $local:Fed
    }
    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "IdentityProviders" -Body $local:Body
}

<#
.SYNOPSIS
Edit an existing SAML external federation identity provider in Safeguard via the Web API.

.DESCRIPTION
Edit an existing external federation identity provider.  Only the supplied
properties are changed; all others are preserved.  This is the cmdlet used to
apply the AADSTS75011 fix by setting -AuthnContextClasses to
urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified so that passwordless /
passkey / FIDO2 sign-in is accepted.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ProviderToEdit
An integer containing an ID or a string containing the name of the external
federation identity provider to edit.

.PARAMETER Name
A string containing a new name for this external federation identity provider.

.PARAMETER Description
A string containing a new description for this external federation identity provider.

.PARAMETER MetadataUrl
An HTTPS URL to the external STS SAML metadata that Safeguard monitors for changes.

.PARAMETER MetadataFile
A path to a local file containing the external STS SAML metadata XML.

.PARAMETER MetadataXml
A string containing the external STS SAML metadata XML.

.PARAMETER NameIdFormat
A string containing the SAML NameID format the external STS will return.

.PARAMETER Realm
A string containing the realm (email domain suffix) used to route users to this provider.

.PARAMETER AuthnContextClasses
A string containing the SAML authentication context class(es) Safeguard will
request.  Set to urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified to allow
passwordless / passkey / FIDO2 sign-in (resolves Entra ID error AADSTS75011).

.PARAMETER AuthnContextComparison
The comparison method used with AuthnContextClasses.  One of Exact, Minimum,
Maximum, or Better.

.PARAMETER RequireAuthentication
Whether the external STS must force re-authentication (SAML ForceAuthn).

.PARAMETER ApplicationIdOverride
A string overriding the application/entity ID Safeguard presents to the external STS.

.PARAMETER ProviderObject
An object containing the existing external federation identity provider with
desired properties set.

.INPUTS
Object representing an external federation identity provider.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardExternalFederationIdentityProvider "Entra ID" -AuthnContextClasses "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"

.EXAMPLE
Edit-SafeguardExternalFederationIdentityProvider -ProviderObject $obj
#>
function Edit-SafeguardExternalFederationIdentityProvider
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=0)]
        [object]$ProviderToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Name,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$MetadataUrl,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$MetadataFile,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$MetadataXml,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$NameIdFormat,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Realm,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$AuthnContextClasses,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateSet("Exact","Minimum","Maximum","Better",IgnoreCase=$true)]
        [string]$AuthnContextComparison,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$RequireAuthentication,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$ApplicationIdOverride,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$ProviderObject
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    }

    process
    {
        if ($PSCmdlet.ParameterSetName -eq "Object")
        {
            if (-not $ProviderObject)
            {
                throw "ProviderObject must not be null"
            }
            $local:EditObject = $ProviderObject
            $local:Id = (Resolve-SafeguardExternalFederationIdentityProviderId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ProviderObject)
        }
        else
        {
            # Only one metadata source may be supplied at a time
            $local:MetadataSources = @("MetadataUrl","MetadataFile","MetadataXml" | Where-Object { $PSBoundParameters.ContainsKey($_) })
            if ($local:MetadataSources.Count -gt 1)
            {
                throw "Specify only one of -MetadataUrl, -MetadataFile, or -MetadataXml"
            }

            $local:Id = (Resolve-SafeguardExternalFederationIdentityProviderId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ProviderToEdit)
            $local:EditObject = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "IdentityProviders/$($local:Id)")

            if (-not $local:EditObject.ExternalFederationProperties)
            {
                $local:EditObject | Add-Member -NotePropertyName ExternalFederationProperties -NotePropertyValue ([PSCustomObject]@{}) -Force
            }
            $local:Fed = $local:EditObject.ExternalFederationProperties

            if ($PSBoundParameters.ContainsKey("Name")) { $local:EditObject.Name = $Name }
            if ($PSBoundParameters.ContainsKey("Description"))
            {
                $local:EditObject | Add-Member -NotePropertyName Description -NotePropertyValue $Description -Force
            }
            if ($PSBoundParameters.ContainsKey("MetadataUrl"))
            {
                $local:Fed | Add-Member -NotePropertyName FederationMetadata -NotePropertyValue $MetadataUrl -Force
            }
            if ($PSBoundParameters.ContainsKey("MetadataFile"))
            {
                if (-not (Test-Path -LiteralPath $MetadataFile))
                {
                    throw "Metadata file '$MetadataFile' does not exist"
                }
                $local:Fed | Add-Member -NotePropertyName FederationMetadata -NotePropertyValue (Get-Content -LiteralPath $MetadataFile -Raw) -Force
            }
            if ($PSBoundParameters.ContainsKey("MetadataXml"))
            {
                $local:Fed | Add-Member -NotePropertyName FederationMetadata -NotePropertyValue $MetadataXml -Force
            }
            if ($PSBoundParameters.ContainsKey("NameIdFormat"))
            {
                $local:Fed | Add-Member -NotePropertyName NameIDFormat -NotePropertyValue $NameIdFormat -Force
            }
            if ($PSBoundParameters.ContainsKey("Realm"))
            {
                $local:Fed | Add-Member -NotePropertyName Realm -NotePropertyValue $Realm -Force
            }
            if ($PSBoundParameters.ContainsKey("AuthnContextClasses"))
            {
                $local:Fed | Add-Member -NotePropertyName AuthnContextClasses -NotePropertyValue $AuthnContextClasses -Force
            }
            if ($PSBoundParameters.ContainsKey("AuthnContextComparison"))
            {
                $local:Fed | Add-Member -NotePropertyName AuthnContextComparison -NotePropertyValue $AuthnContextComparison -Force
            }
            if ($PSBoundParameters.ContainsKey("RequireAuthentication"))
            {
                $local:Fed | Add-Member -NotePropertyName RequireAuthentication -NotePropertyValue ([bool]$RequireAuthentication) -Force
            }
            if ($PSBoundParameters.ContainsKey("ApplicationIdOverride"))
            {
                $local:Fed | Add-Member -NotePropertyName ApplicationIdOverride -NotePropertyValue $ApplicationIdOverride -Force
            }
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "IdentityProviders/$($local:Id)" -Body $local:EditObject
    }
}

<#
.SYNOPSIS
Remove a SAML external federation identity provider from Safeguard via the Web API.

.DESCRIPTION
Delete an existing external federation identity provider.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ProviderToDelete
An integer containing an ID or a string containing the name of the external
federation identity provider to delete.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardExternalFederationIdentityProvider "Entra ID"
#>
function Remove-SafeguardExternalFederationIdentityProvider
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ProviderToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Id = (Resolve-SafeguardExternalFederationIdentityProviderId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ProviderToDelete)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "IdentityProviders/$($local:Id)"
}

<#
.SYNOPSIS
Force a refresh of an external federation provider's SAML metadata via the Web API.

.DESCRIPTION
When an external federation provider is configured with an HTTPS metadata URL,
Safeguard periodically downloads it to check for updates.  This cmdlet triggers
an immediate refresh, for example after rotating the external STS's signing
certificate.  The refresh is also propagated to other nodes in a cluster.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ProviderToSync
An integer containing an ID or a string containing the name of the external
federation identity provider to refresh.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Sync-SafeguardExternalFederationIdentityProvider "Entra ID"
#>
function Sync-SafeguardExternalFederationIdentityProvider
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ProviderToSync
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Id = (Resolve-SafeguardExternalFederationIdentityProviderId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ProviderToSync)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "IdentityProviders/$($local:Id)/UpdateFederationMetadataFromUrl"
}

<#
.SYNOPSIS
Get Safeguard's SAML service provider metadata via the RSTS.

.DESCRIPTION
Safeguard's embedded security token service (RSTS) publishes SAML service
provider metadata that you supply to an external SAML identity provider (such as
Microsoft Entra ID) when configuring external federation.  This cmdlet retrieves
that metadata anonymously from the appliance.  By default it returns the parsed
service provider properties (entity ID, assertion consumer service URLs, etc.).

Use -OutFile to instead save the raw metadata XML to a file.  The value you give
-OutFile controls the destination:
  - -OutFile .                  -> a default-named file in the current directory
  - -OutFile <existing folder>  -> a default-named file in that folder
  - -OutFile <file path>        -> written to exactly that path

The default file name is <appliance>-SamlServiceProviderMetadata.xml.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.  Falls back to the current
session appliance when omitted.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutFile
Save the raw metadata XML to a file instead of returning parsed properties.  If
the value is an existing directory (including "." for the current directory) a
default-named file is written into it; otherwise it is treated as the target file
path.

.INPUTS
None.

.OUTPUTS
Parsed service provider properties, or a System.IO.FileInfo when -OutFile is used.

.EXAMPLE
Get-SafeguardSamlMetadata spp1.dan.test -Insecure

.EXAMPLE
Get-SafeguardSamlMetadata spp1.dan.test -Insecure -OutFile .

.EXAMPLE
Get-SafeguardSamlMetadata spp1.dan.test -Insecure -OutFile C:\temp

.EXAMPLE
Get-SafeguardSamlMetadata spp1.dan.test -Insecure -OutFile .\entra-sp-metadata.xml
#>
function Get-SafeguardSamlMetadata
{
    [CmdletBinding(DefaultParameterSetName="Properties")]
    [OutputType([PSCustomObject],[System.IO.FileInfo])]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="File",Mandatory=$true,Position=1)]
        [string]$OutFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Appliance -and $SafeguardSession)
    {
        $Appliance = $SafeguardSession["Appliance"]
        if (-not $PSBoundParameters.ContainsKey("Insecure"))
        {
            $Insecure = $SafeguardSession["Insecure"]
        }
    }
    if (-not $Appliance)
    {
        $Appliance = (Read-Host "Appliance")
    }

    $local:Url = "https://$Appliance/RSTS/Saml2FedMetadata"

    try
    {
        if ($Insecure)
        {
            Disable-SslVerification
        }
        $local:WebArgs = @{ Uri = $local:Url; Method = "GET"; UseBasicParsing = $true }
        foreach ($local:Pref in (Get-SafeguardSslPreferences).GetEnumerator())
        {
            # Keys are qualified (Invoke-WebRequest:SkipCertificateCheck); strip the prefix
            $local:WebArgs[($local:Pref.Key -split ":")[-1]] = $local:Pref.Value
        }

        $local:Response = (Invoke-WebRequest @local:WebArgs)
        if ($local:Response.Content -is [byte[]])
        {
            $local:Xml = [System.Text.Encoding]::UTF8.GetString($local:Response.Content)
        }
        else
        {
            $local:Xml = $local:Response.Content
        }
        # Strip a byte-order mark if present so [xml] parsing does not choke
        $local:Xml = $local:Xml.TrimStart([char]0xFEFF)
    }
    finally
    {
        if ($Insecure)
        {
            Enable-SslVerification
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:DefaultName = "$Appliance-SamlServiceProviderMetadata.xml"
        $local:Target = $OutFile

        # A trailing separator or an existing folder means "put the default-named file in here"
        $local:LooksLikeDir = $local:Target.EndsWith("\") -or $local:Target.EndsWith("/") -or `
                              (Test-Path -LiteralPath $local:Target -PathType Container)

        if (-not [System.IO.Path]::IsPathRooted($local:Target))
        {
            $local:Target = Join-Path (Get-Location).Path $local:Target
        }

        if ($local:LooksLikeDir)
        {
            $local:FullPath = Join-Path $local:Target $local:DefaultName
        }
        else
        {
            $local:FullPath = $local:Target
        }

        # Make sure the destination directory exists so the file lands where requested
        $local:DestDir = [System.IO.Path]::GetDirectoryName($local:FullPath)
        if ($local:DestDir -and -not (Test-Path -LiteralPath $local:DestDir -PathType Container))
        {
            New-Item -ItemType Directory -Path $local:DestDir -Force | Out-Null
        }

        # Write UTF-8 without BOM
        $local:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($local:FullPath, $local:Xml, $local:Utf8NoBom)
        Get-Item -LiteralPath $local:FullPath
        return
    }

    [xml]$local:MetadataDoc = $local:Xml
    $local:Ed = $local:MetadataDoc.EntityDescriptor
    $local:Sp = $local:Ed.SPSSODescriptor

    $local:Acs = @($local:Sp.AssertionConsumerService | ForEach-Object {
        [PSCustomObject]@{
            Index     = $_.index
            IsDefault = $_.isDefault
            Binding   = $_.Binding
            Location  = $_.Location
        }
    })
    $local:Slo = @($local:Sp.SingleLogoutService | ForEach-Object {
        [PSCustomObject]@{
            Binding  = $_.Binding
            Location = $_.Location
        }
    })

    [PSCustomObject]@{
        EntityId                   = $local:Ed.entityID
        AssertionConsumerServices  = $local:Acs
        SingleLogoutServices       = $local:Slo
        NameIdFormats              = @($local:Sp.NameIDFormat)
        AuthnRequestsSigned        = $local:Sp.AuthnRequestsSigned
        WantAssertionsSigned       = $local:Sp.WantAssertionsSigned
        MetadataUrl                = $local:Url
        RawMetadata                = $local:Xml
    }
}
