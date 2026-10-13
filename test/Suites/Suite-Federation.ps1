@{
    Name        = "External Federation"
    Description = "Tests SAML provider lifecycle, field projections, and federated user creation"
    Tags        = @("federation", "users", "core")

    Setup = {
        param($Context)

        $name = "$($Context.TestPrefix)_Federation"
        $userName = "$($Context.TestPrefix)_FederatedUser"
        Remove-SgPsStaleTestObject -Collection "Users" -Name $userName
        Remove-SgPsStaleTestObject -Collection "IdentityProviders" -Name $name

        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            (Join-Path $Context.TestRoot "TestData\CERTS\RootCA.cer"))
        try {
            $publicCertificate = [Convert]::ToBase64String($certificate.RawData)
        }
        finally {
            $certificate.Dispose()
        }
        $realm = "$($Context.TestPrefix.ToLowerInvariant()).example.invalid"
        $metadata = @"
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://$realm">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>$publicCertificate</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://$realm/saml"/>
  </IDPSSODescriptor>
</EntityDescriptor>
"@
        $provider = New-SafeguardExternalFederationIdentityProvider -Insecure -Name $name `
            -Realm $realm -MetadataXml $metadata -Description "Federation integration test" `
            -RequireAuthentication -AuthnContextComparison Exact
        $Context.SuiteData["Provider"] = $provider
        $Context.SuiteData["ProviderId"] = $provider.Id
        $Context.SuiteData["ProviderName"] = $name
        $Context.SuiteData["Realm"] = $realm
        $Context.SuiteData["UserName"] = $userName
        Register-SgPsTestCleanup -Description "Remove test federation provider" -Action {
            param($Ctx)
            if (-not $Ctx.SuiteData["ProviderDeleted"]) {
                Remove-SafeguardExternalFederationIdentityProvider -Insecure $Ctx.SuiteData["ProviderId"]
            }
        }
    }

    Execute = {
        param($Context)

        Test-SgPsAssert "Creating a federation provider returns its type and realm" {
            $provider = $Context.SuiteData["Provider"]
            $provider.Id -gt 0 -and $provider.TypeReferenceName -eq "ExternalFederation" -and
                $provider.ExternalFederationProperties.Realm -eq $Context.SuiteData["Realm"]
        }
        Test-SgPsAssert "Federation provider persists and resolves by name" {
            $provider = Get-SafeguardExternalFederationIdentityProvider -Insecure $Context.SuiteData["ProviderName"]
            $provider.Id -eq $Context.SuiteData["ProviderId"] -and
                $provider.ExternalFederationProperties.RequireAuthentication -eq $true
        }
        Test-SgPsAssert "Listing with Id and Name returns only federated providers and requested fields" {
            $all = @(Get-SafeguardExternalFederationIdentityProvider -Insecure)
            $projected = @(Get-SafeguardExternalFederationIdentityProvider -Insecure -Fields Id,Name)
            $expectedIds = @($all.Id | Sort-Object)
            $actualIds = @($projected.Id | Sort-Object)
            $unexpectedFields = @($projected | ForEach-Object { $_.PSObject.Properties.Name } |
                Where-Object { $_ -notin @("Id", "Name") })
            $actualIds.Count -gt 0 -and ($expectedIds -join ",") -eq ($actualIds -join ",") -and
                $unexpectedFields.Count -eq 0
        }
        Test-SgPsAssert "Listing retains an explicitly requested provider type" {
            $projected = @(Get-SafeguardExternalFederationIdentityProvider -Insecure -Fields Id,TypeReferenceName)
            $matching = @($projected | Where-Object { $_.Id -eq $Context.SuiteData["ProviderId"] })
            $matching.Count -eq 1 -and $matching[0].TypeReferenceName -eq "ExternalFederation"
        }
        Test-SgPsAssert "Listing preserves nested field projections" {
            $projected = @(Get-SafeguardExternalFederationIdentityProvider -Insecure `
                -Fields Id,ExternalFederationProperties.Realm)
            $matching = @($projected | Where-Object { $_.Id -eq $Context.SuiteData["ProviderId"] })
            $matching.Count -eq 1 -and
                $matching[0].ExternalFederationProperties.Realm -eq $Context.SuiteData["Realm"] -and
                $matching[0].PSObject.Properties.Name -notcontains "TypeReferenceName"
        }
        Test-SgPsAssert "Retrieving a provider by ID respects requested fields" {
            $provider = Get-SafeguardExternalFederationIdentityProvider -Insecure `
                $Context.SuiteData["ProviderId"] -Fields Id,Name
            $provider.Id -eq $Context.SuiteData["ProviderId"] -and
                $provider.Name -eq $Context.SuiteData["ProviderName"] -and
                $provider.PSObject.Properties.Name -notcontains "TypeReferenceName"
        }
        Test-SgPsAssertThrows "Federation lookup rejects a local identity provider" {
            Get-SafeguardExternalFederationIdentityProvider -Insecure -ProviderToGet -1
        } -ExpectedMessage "*not ExternalFederation*"
        Test-SgPsAssert "Editing authentication context preserves unrelated properties" {
            $before = Get-SafeguardExternalFederationIdentityProvider -Insecure $Context.SuiteData["ProviderId"]
            Edit-SafeguardExternalFederationIdentityProvider -Insecure $Context.SuiteData["ProviderId"] `
                -AuthnContextClasses "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" `
                -RequireAuthentication:$false | Out-Null
            $after = Get-SafeguardExternalFederationIdentityProvider -Insecure $Context.SuiteData["ProviderId"]
            $after.ExternalFederationProperties.AuthnContextClasses -eq
                "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" -and
                $after.ExternalFederationProperties.RequireAuthentication -eq $false -and
                $after.ExternalFederationProperties.Realm -eq $before.ExternalFederationProperties.Realm -and
                $after.Description -eq $before.Description -and
                $after.ExternalFederationProperties.AuthnContextComparison -eq
                    $before.ExternalFederationProperties.AuthnContextComparison
        }
        Test-SgPsAssert "Creating a federated user sets the provider and name claim" {
            $identity = "$($Context.SuiteData["UserName"])@$($Context.SuiteData["Realm"])"
            $user = New-SafeguardUser -Insecure -Provider $Context.SuiteData["ProviderName"] `
                -NewUserName $Context.SuiteData["UserName"] -Identity $identity -FirstName "Federated"
            $Context.SuiteData["UserId"] = $user.Id
            $Context.SuiteData["Identity"] = $identity
            Register-SgPsTestCleanup -Description "Remove test federated user" -Action {
                param($Ctx)
                if (-not $Ctx.SuiteData["UserDeleted"]) {
                    Remove-SafeguardUser -Insecure -UserToDelete $Ctx.SuiteData["UserId"]
                }
            }
            $user.Id -gt 0 -and $user.PrimaryAuthenticationProvider.Id -eq $Context.SuiteData["ProviderId"] -and
                $user.PrimaryAuthenticationProvider.Identity -eq $identity
        }
        Test-SgPsAssert "Federated user identity persists" {
            $user = Get-SafeguardUser -Insecure $Context.SuiteData["UserId"]
            $user.PrimaryAuthenticationProvider.Id -eq $Context.SuiteData["ProviderId"] -and
                $user.PrimaryAuthenticationProvider.Identity -eq $Context.SuiteData["Identity"] -and
                $user.FirstName -eq "Federated"
        }
        Test-SgPsAssert "Removing a federation provider persists after removing its user" {
            Remove-SafeguardUser -Insecure -UserToDelete $Context.SuiteData["UserId"]
            $Context.SuiteData["UserDeleted"] = $true
            Remove-SafeguardExternalFederationIdentityProvider -Insecure $Context.SuiteData["ProviderId"]
            $Context.SuiteData["ProviderDeleted"] = $true
            $remaining = @(Get-SafeguardExternalFederationIdentityProvider -Insecure)
            $remaining.Id -notcontains $Context.SuiteData["ProviderId"]
        }
    }

    Cleanup = {
        param($Context)
    }
}
