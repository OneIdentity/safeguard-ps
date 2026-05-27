# Redact authentication plumbing (auth headers, cookies, tokens) before they
# are written to verbose/debug streams. Does not touch API request/response
# data fields.
#
# Rules:
#   * Top-level keys ONLY. No recursion into nested objects.
#   * EXACT case-insensitive key match against a fixed allowlist.
#   * String-valued leaves ONLY. Non-string values pass through.
#   * Authorization: preserves the scheme prefix (Bearer/Basic), redacts
#     only the credential portion.
#   * Input is NEVER mutated. A shallow copy is returned.

$script:RedactionAllowlist = @(
    'Authorization',
    'Cookie',
    'Set-Cookie',
    'access_token',
    'refresh_token',
    'id_token',
    'UserToken'
)

function Hide-AuthHeaderValue
{
    <#
    .SYNOPSIS
        Returns a redacted form of an HTTP Authorization header value.

    .DESCRIPTION
        Preserves the "Bearer " or "Basic " scheme prefix and replaces the
        credential portion with the literal "[REDACTED]". Unknown schemes
        and empty / non-string input collapse to "[REDACTED]" with no leak.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$false, Position=0)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    if ($null -eq $Value -or -not ($Value -is [string]) -or [string]::IsNullOrWhiteSpace($Value))
    {
        return '[REDACTED]'
    }

    if ($Value -match '^\s*[Bb][Ee][Aa][Rr][Ee][Rr]\s+')
    {
        return 'Bearer [REDACTED]'
    }
    if ($Value -match '^\s*[Bb][Aa][Ss][Ii][Cc]\s+')
    {
        return 'Basic [REDACTED]'
    }
    return '[REDACTED]'
}

function Hide-SdkPlumbing
{
    <#
    .SYNOPSIS
        Returns a shallow copy of $InputObject with SDK authentication
        plumbing redacted, suitable for verbose/debug logging.

    .DESCRIPTION
        Redacts SDK auth plumbing from a hashtable or PSCustomObject.
        See the header of redaction.psm1 for the full rules. The input
        is never mutated.

    .PARAMETER InputObject
        A hashtable, IDictionary, or PSCustomObject. Other types and $null
        are returned unchanged.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param(
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [AllowNull()]
        $InputObject
    )

    Process
    {
        if ($null -eq $InputObject)
        {
            return $null
        }

        $isCustom = $InputObject -is [System.Management.Automation.PSCustomObject]
        $isDict   = $InputObject -is [System.Collections.IDictionary]
        if (-not $isCustom -and -not $isDict)
        {
            return $InputObject
        }

        $result = @{}
        if ($isDict)
        {
            foreach ($k in $InputObject.Keys)
            {
                $result[$k] = $InputObject[$k]
            }
        }
        else
        {
            foreach ($p in $InputObject.PSObject.Properties)
            {
                $result[$p.Name] = $p.Value
            }
        }

        $keysSnapshot = @($result.Keys)
        foreach ($key in $keysSnapshot)
        {
            $match = $null
            foreach ($allowed in $script:RedactionAllowlist)
            {
                if ([string]::Equals($key, $allowed, [System.StringComparison]::OrdinalIgnoreCase))
                {
                    $match = $allowed
                    break
                }
            }
            if ($null -eq $match) { continue }

            $val = $result[$key]
            if (-not ($val -is [string])) { continue }

            if ([string]::Equals($match, 'Authorization', [System.StringComparison]::OrdinalIgnoreCase))
            {
                $result[$key] = Hide-AuthHeaderValue -Value $val
            }
            else
            {
                $result[$key] = '[REDACTED]'
            }
        }

        return $result
    }
}

# Backwards-compatible aliases. PSScriptAnalyzer requires approved verbs
# (Hide is approved; Redact is not).
Set-Alias -Name Redact-SdkPlumbing    -Value Hide-SdkPlumbing
Set-Alias -Name Redact-AuthHeaderValue -Value Hide-AuthHeaderValue

Export-ModuleMember `
    -Function Hide-SdkPlumbing, Hide-AuthHeaderValue `
    -Alias    Redact-SdkPlumbing, Redact-AuthHeaderValue
