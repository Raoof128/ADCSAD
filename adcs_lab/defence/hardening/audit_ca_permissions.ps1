<#
Audit CA ACLs for ESC5 exposures.
#>

$cas = Get-CertificationAuthority
foreach($ca in $cas){
    Write-Host "[+] Auditing $($ca.Name)"
    $acl = Get-CACrlDistributionPointAcl -CertificationAuthority $ca
    $acl.Access | Where-Object {$_.IdentityReference -in @("Authenticated Users","Domain Users") -and $_.FileSystemRights -match "Manage"} |
        ForEach-Object { Write-Warning "[!] ESC5 risk: $($_.IdentityReference) has $($_.FileSystemRights)" }
}
