<#
.SYNOPSIS
    Powershell Script to write the secretserver folder IDs of ss_Generate-Secret.ps1 into netbox
.DESCRIPTION
    Reads the newest result CSV of ss_Generate-Secret.ps1 (ss_Generate-Secret_*.csv in this folder) and sets the
    custom field Credential_Folder_ID of the netbox site with the same Job_Nummer to the FolderId of the row.
    Rows without FolderId and JobNrs with no or more than one netbox site are skipped with a warning.
    A site whose Credential_Folder_ID already holds another folder ID is not changed (warning).
    Run with -WhatIf to see the changes without writing them.
    Uses the personal IPAM token stored for the current user by the module BiCANetboxMain
    (HKCU:\Software\BiCA\NetboxClient, as in CiRRUS_Configurator); asks for it once if none is stored.
    The token needs write permission on sites.
.PARAMETER CsvPath
    Result CSV to import instead of the newest one.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param([string]$CsvPath)

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[string]$NetboxApi = 'https://ipam.lantzerath-group.com/api'

if (!$CsvPath) { $CsvPath = (Get-ChildItem -Path "$PSScriptRoot\ss_Generate-Secret_*.csv" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName }
if (!$CsvPath -or !(Test-Path -Path $CsvPath)) {Write-Host "No result CSV of ss_Generate-Secret.ps1 found in $PSScriptRoot - Aborting Script" -ForegroundColor Red ; exit}

$AllRows = @(Import-Csv -Path $CsvPath -Delimiter ';' -Encoding UTF8)
$Rows = @($AllRows | Where-Object { "$($_.FolderId)" -match '^\d+$' })
Write-Host "Importing $CsvPath ($($Rows.Count) of $($AllRows.Count) rows with FolderId)"
foreach ($Row in ($AllRows | Where-Object { "$($_.FolderId)" -notmatch '^\d+$' })) {
    Write-Host "JobNr $($Row.JobNr): no FolderId (Status $($Row.Status)) - skipped" -ForegroundColor Yellow
}
if (!$Rows) {Write-Host "No rows with FolderId in $CsvPath - Aborting Script" -ForegroundColor Red ; exit}

# Personal netbox token from the registry via BiCANetboxMain (latest version from the public repo, removed again
# right after use). -WhatIf:$false so that -WhatIf of this script doesn't skip extracting and cleaning up the module.
$ModuleZip = Join-Path $PSScriptRoot 'BiCANetboxMain.zip'
$ModulePath = Join-Path $PSScriptRoot 'BiCANetboxMain.psm1'
$ModuleManifest = Join-Path $PSScriptRoot 'BiCANetboxMain.psd1'
$NetboxToken = $null
try {
    # DPAPI (ProtectedData) is not loaded by default in Windows PowerShell 5.1
    if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) { Add-Type -AssemblyName System.Security }
    Invoke-WebRequest -Uri 'https://bicacdn.blob.core.windows.net/download/publicrepo/scripts/BiCANetboxMain.zip' -OutFile $ModuleZip -UseBasicParsing
    Unblock-File -Path $ModuleZip -WhatIf:$false
    Expand-Archive -Path $ModuleZip -DestinationPath $PSScriptRoot -Force -WhatIf:$false
    Get-Module -Name BiCANetboxMain -All | Remove-Module -Force -WhatIf:$false
    Import-Module $ModulePath -WarningAction Ignore -ErrorAction Stop

    $NetboxToken = Initialize-PersonalNetboxToken
    if (!$NetboxToken) {
        $Token = Read-Host 'No personal IPAM Token stored yet - please provide it once (https://ipam.lantzerath-group.com/user/api-tokens/)' -AsSecureString
        $NetboxToken = Initialize-PersonalNetboxToken -NetboxToken (New-Object System.Management.Automation.PSCredential 'IPAM', $Token).GetNetworkCredential().Password
    }
}
catch {Write-Host "Netbox token not available: $($_.Exception.Message) - Aborting Script" -ForegroundColor Red ; exit}
finally {
    Get-Module -Name BiCANetboxMain -All | Remove-Module -Force -WhatIf:$false
    Remove-Item -Path $ModuleZip, $ModulePath, $ModuleManifest -Force -ErrorAction SilentlyContinue -WhatIf:$false
}
if (!$NetboxToken) {Write-Host "No netbox token available - Aborting Script" -ForegroundColor Red ; exit}

$Headers = @{
    Authorization = "Token $NetboxToken"
    Accept        = 'application/json'
}


foreach ($Row in $Rows) {
    $FolderId = [int]$Row.FolderId
    try {
        $Sites = @((Invoke-RestMethod -Headers $Headers -Method Get -Uri "$NetboxApi/dcim/sites/?cf_Job_Nummer=$($Row.JobNr)").results)
        if ($Sites.Count -ne 1) {
            Write-Host "JobNr $($Row.JobNr): $($Sites.Count) netbox sites with this Job_Nummer - skipped" -ForegroundColor Yellow
            continue
        }
        $Site = $Sites[0]

        # 0 or empty means not set (same as SupportLauncher\collect_credentials.ps1)
        $CurrentId = [int]$Site.custom_fields.Credential_Folder_ID
        if ($CurrentId -eq $FolderId) {
            Write-Host "Site '$($Site.name)' (ID $($Site.id)): Credential_Folder_ID is already $FolderId"
            continue
        }
        if ($CurrentId -ne 0) {
            Write-Host "Site '$($Site.name)' (ID $($Site.id)): Credential_Folder_ID is $CurrentId, not $FolderId - skipped" -ForegroundColor Yellow
            continue
        }

        if ($PSCmdlet.ShouldProcess("Site '$($Site.name)' (ID $($Site.id))", "Set Credential_Folder_ID to $FolderId")) {
            $body = @{ custom_fields = @{ Credential_Folder_ID = $FolderId } } | ConvertTo-Json

            $null = Invoke-RestMethod -Headers $Headers -ContentType 'application/json; charset=utf-8' -Method Patch -Body ([Text.Encoding]::UTF8.GetBytes($body)) -Uri "$NetboxApi/dcim/sites/$($Site.id)/"
            Write-Host "Site '$($Site.name)' (ID $($Site.id)): Credential_Folder_ID set to $FolderId" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error for JobNr $($Row.JobNr): $($_.Exception.Message) $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
}

# SIG # Begin signature block
# MIIu8AYJKoZIhvcNAQcCoIIu4TCCLt0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCtI4bLRohTZ7Jn
# qL9lSx46zhRMRFH8jAoqb3mOzVxqXKCCE5wwggWQMIIDeKADAgECAhAFmxtXno4h
# MuI5B72nd3VcMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0xMzA4MDExMjAwMDBaFw0z
# ODAxMTUxMjAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/z
# G6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZ
# anMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7s
# Wxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL
# 2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfb
# BHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3
# JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3c
# AORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqx
# YxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0
# viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aL
# T8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjQjBAMA8GA1Ud
# EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzANBgkqhkiG9w0BAQwFAAOCAgEAu2HZfalsvhfEkRvDoaIAjeNk
# aA9Wz3eucPn9mkqZucl4XAwMX+TmFClWCzZJXURj4K2clhhmGyMNPXnpbWvWVPjS
# PMFDQK4dUPVS/JA7u5iZaWvHwaeoaKQn3J35J64whbn2Z006Po9ZOSJTROvIXQPK
# 7VB6fWIhCoDIc2bRoAVgX+iltKevqPdtNZx8WorWojiZ83iL9E3SIAveBO6Mm0eB
# cg3AFDLvMFkuruBx8lbkapdvklBtlo1oepqyNhR6BvIkuQkRUNcIsbiJeoQjYUIp
# 5aPNoiBB19GcZNnqJqGLFNdMGbJQQXE9P01wI4YMStyB0swylIQNCAmXHE/A7msg
# dDDS4Dk0EIUhFQEI6FUy3nFJ2SgXUE3mvk3RdazQyvtBuEOlqtPDBURPLDab4vri
# RbgjU2wGb2dVf0a1TD9uKFp5JtKkqGKX0h7i7UqLvBv9R0oN32dmfrJbQdA75PQ7
# 9ARj6e/CVABRoIoqyc54zNXqhwQYs86vSYiv85KZtrPmYQ/ShQDnUBrkG5WdGaG5
# nLGbsQAe79APT0JsyQq87kP6OnGlyE0mpTX9iV28hWIdMtKgK1TtmlfB2/oQzxm3
# i0objwG2J5VT6LaJbVu8aNQj6ItRolb58KaAoNYes7wPD1N1KarqE3fk3oyBIa0H
# EEcRrYc9B9F1vM/zZn4wggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0G
# CSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTla
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C
# 0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce
# 2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0da
# E6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6T
# SXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoA
# FdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7Oh
# D26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM
# 1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z
# 8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05
# huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNY
# mtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP
# /2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATAN
# BgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95Ry
# sQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HL
# IvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5Btf
# Q/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnh
# OE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIh
# dXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV
# 9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/j
# wVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYH
# Ki8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmC
# XBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l
# /aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZW
# eE4wggdQMIIFOKADAgECAhAPXrvxQ6T1tsiZa78xatEWMA0GCSqGSIb3DQEBCwUA
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwHhcNMjUwNTAyMDAwMDAwWhcNMjgwNzI4MjM1OTU5WjBYMQsw
# CQYDVQQGEwJDSDEQMA4GA1UECBMHTHVjZXJuZTETMBEGA1UEBxMKUm90aGVuYnVy
# ZzEQMA4GA1UEChMHQklDQSBBRzEQMA4GA1UEAxMHQklDQSBBRzCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAJPjaY1psbAAxhijsoHS7zeaNTAID1ZJ8G7V
# QwvtbJUbUnYIZ62pJrRRaNOtC15T2r4ZY3q0FRiF7mKocOj2GX4kDBlmWWl9Eixc
# ctfS2vXjmT67+3chxhKG8eU7oyxCOLbDFAJN5kwmRQqUgp0A7f9gUc1aI479ZfRn
# 4jACgGC/g/n6VusikJQpbCIgFNEhwPGOIQThdFRN2rM3W4pdRoGwbbHMD5F3yRKy
# KzcI+DGxnJU7vKCl7oBsMglDtd2PrM1vGfmts0CKChvIpq34bPBG36jTrCjftpVy
# QRevhXcxhGC3gL5ppoldSxheO4fTPTj0lKnjN1fBtcqrZrmDPdTR1i+QVwJRJ+4U
# V0/FTl+B8PBKIVAoqIP9hXzHdOPkg+en0FSaWMTR6MTBXZ0a8r6h7MTqQHudqokw
# izkntnWRLJR+buemduNVB1DyLBDMqyyAGdD99pYNHnY+sFA3ZZ/wpG+vVMDGPHih
# 8VYK4zZQ5yP65TkD6SmEyIKEsoqVJUZ1dvxlWXAsuVTK3Fy92RCXwhYwxx4RK3iY
# glMejHLkJicHft5VyV97GMw329BWnWq/W0rHSDlJBJXV0556+ELhFzotFSHQIKdB
# yBUGfQUpw07BRes9MJJRDXl8lJR/mUHc+UBAMxUee5xoXvjhZChANu4inrD2sjoW
# 1a8qc7e3AgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQUN2o03IIuwROf/ZYtj2Ii9z/K12gwPgYDVR0gBDcwNTAz
# BgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBACis4HqO6fNOxKdycfPwV6+VCr2oPiN/kDeq
# Mhe+XzDcghqla6hXPNjbhvoHZ/aujB1adN07diiHeV63obZ/2b4APofdyCnH6reF
# 5eZVWYsk88BGPzisjBXCqQNGpmEuFaLqmcXn+gr7VFzAamjfeOKv/0TcyImq9Q85
# jxndNNkKbHi/MSzhGHbjFA8uqz4CMgTJM/v38gHzQesowIJo97VC8qUsO6vvayPX
# g8I4m54HZVYqkeQ2+6sqQ/xnV1XYkmaXI2A8eb4tHjyllijHrnXbthBLK9RBc8uN
# gPrk0loxipromLzHxDJWRoehYoJYgHqNAQNVWRdR37KELruLhILDMoU8ilItBBXn
# Uij0vMWMj0IoEgKXp1w/wfb1J0IlOYP+bR6CsVaELm8vV27mfW4O+ClGxIEdcO0B
# QED5reYwGBFYjLfVZREg+rIaozA/FzUaizMzgTbYejPCwt+ID4Zyoxky0rG5Dedj
# 6ClSlXhPatAVYw4ltoDncT42/6+k4mE1NE70s2gNAW8hjU7rwG0OdSB5OM4/NZXB
# nHV1bqnCEG9lqJnIbZ1wh0j5lTbMvnsYX/XOPupvDL0XYEte8EtM1Hp5nLbgPd2a
# DhSpSClbofNnCR90e3tG5AC/rsnWSUz5WdyaoDJMLVqSQEo5OVLKfMuqAOuVhsOv
# v1EGSTqxMYIaqjCCGqYCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAPXrvxQ6T1tsiZa78xatEW
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIPNdGS/goQ4YHqsJ6YPSlplPjIFHerbieR4V
# 6eXjiPaoMA0GCSqGSIb3DQEBAQUABIICAImfk2YY00uKeAOsmzNRIvDX4fF9l0l+
# /dW9+E3kEKHjlZX1Bdcxr2cymVgT0oW34bkvuxQu7Bs1Q+3cP1iiImN9Himfdyxb
# gfeFQPQgfLWOvSHg/2jR2VYUfa/+1AI+9OQPV4znWmjehjOZLPM3Jh0eEGTZS6/K
# KL6XUC4Op+KfzhCKYkVAWXbjvBrzNhoTeHTbAUHqMhg/gci0/znaEzIGIe0IN0Xd
# Z64H5mjxTe2VsyRsfZX28lLOmcywhgPwYonvynvV7cXHsRsGEfZdRKIo5QDjfZSF
# GLc+3469WVs3Rtzc0IrtgtMtfaGhUTJuJombLapfWFKraD2SSkDrPcrxbD+fmoEY
# AuwVoFG5l2NNn7EAqMzjUkZ3Caan+ZU2NWCkW7FrwM7s5WSK3irQk6VkH/8gx8ks
# nP4CetC1+rObf8+yFLwH/Y1bpbmc/lqs5pYOy47P9bki/yU3T9XQ+YleHw/BNjrU
# WbGG4e09qar98fpesrwnn3Q0JN2Zsx0oFjE0SJa8EZo9dXaplET/XuuTyWoicw9K
# Xs9szEOb03bMwJD5lnfl0TOGNv64o1/mOAKNzHOIqRWEtzFNnzKSXgCYAXGf0bQl
# EOAGvTcvAwZ2iUp2XMF5WN7vgMAMh/Nt3E3dldZykKs9NByxUJ7HspVUIhXICNRV
# cBhPXfNLpCXJoYIXdzCCF3MGCisGAQQBgjcDAwExghdjMIIXXwYJKoZIhvcNAQcC
# oIIXUDCCF0wCAQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBKBpBGcw
# ZQIBAQYJYIZIAYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEIHiqIqj1znm53zVW87TH
# XB9yH+LNK05+OKuxhMBJIiSTAhEA4KtF0E6sFQuJ2ee3D2q6PhgPMjAyNjEwMTkx
# MTIzMDhaoIITOjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZI
# hvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0
# MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5
# NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRl
# ciAyMDI2IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7N
# SvjUm0xls/04xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA
# 31N2D9ATMbfZdw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLG
# bA8DtwUpFMQ4yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cro
# s1czRSmWRHqMv9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0
# fkjG426xDr2d3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91
# EZtukGWDJ/xZ27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV
# /mxUbCKJb8pBNY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJu
# XaB/0nKWmQmVZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDT
# LtT0+aa1vN71fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNN
# hg8MtDg43c4tMZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLX
# cK6HM5PYnH5X+eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/
# BAIwADAdBgNVHQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU
# 729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0
# MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNB
# NDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji
# 8sEi2g10CBDaMiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlD
# HgKRLa3xoc+OReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+
# FDYAHWZHx4R79ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDw
# K+hgGMs0gNNp1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vl
# Ik3zPKQ+ylcheWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7o
# NgC/r+Y4bSlZ3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2
# HLEHklpryqs6QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tT
# uW9x0eXh7NDc1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joi
# QSPsWRGxkbDDW15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4
# ngCI1moJCTbevGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYU
# o80r3TfMlkD0/YMwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwF
# ADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElE
# IFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKn
# JS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/W
# BTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHi
# LQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhm
# V1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHE
# tWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6
# MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mX
# aXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZ
# xd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfh
# vbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvl
# EFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn1
# 5GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
# HQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4Ix
# LVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290
# Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAA
# MA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzs
# hV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre
# +i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8v
# C6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38
# dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNr
# Iv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDfDCCA3gCAQEw
# fTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExAhAIT9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoIHR
# MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYx
# MDE5MTEyMzA4WjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBRR2avaA0lz2E9CZqyk
# gkjms2nEOTAvBgkqhkiG9w0BCQQxIgQgfBJVKMRN/e2fpX6MBFhuFWXGPyiGkFB8
# xEavcUxK/TMwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgLaCdp/QTH5/nLbbF5unJ
# ZWdVrwQ/HqdCzA0hIOFB6/wwDQYJKoZIhvcNAQEBBQAEggIAEySHNQ0oxigH2mas
# ITfq8bTTl8b6aUdRaYZF02Y4pMXzG5vSPgiIIPnhcWhKjr9SDmT04Nq4R5dNcycw
# L6+CrJMKR5dI++1cHk7lAVFeB1L34gFh4RrDDsrpSpmhjEhxA6BWKH4iqF36jQt8
# XhhXqrBpznq9ulR/7gnXi6TRH9yL5MbMMpu2Blekqo9a47AMCWYEYPjqsDFLmT0I
# /uYl0TUpXjF4PqQoVsFJcGGUxKAu1dwJvdGwJryI5ebkx0qKtutTE46fhY8JtUDf
# n3hB4p4jrBH/e9uQMAI/Yy0CwWd7Bb/duKv5TlSg4dz0BPuDuWAY7S539vf42+/h
# T9OZ2MGSrVj5+C9B4HMxwIqbyWZAUgUaZXl8YcOfrKp/N06zLWMrSCxE4jCvWtcH
# ZBXMruk/V+TYybPSPIN2wfPX8fcvXdGQhGikhpmhWb21M18m38WHcPoSth9XHJdz
# SQUL+TOHlX4h4gNrxBxsVca3pm/oZ+X0NONkMx4FGII+L8pG7g4YFT94bVKE4E/1
# LffGpn5thztHjr85qNu2E7sgV6Lb8qsfI/+i8xlgQVMVCov04fVvHd+qPW9wT4Xc
# kMkQwZgmoEpUA+g2oGUJNo5gy1TkOmAatyirkgWfbEfTWZDNCtwiOIVM8DEjjNIH
# tCTzcmO1922roBss/kWUlibrrmE=
# SIG # End signature block
