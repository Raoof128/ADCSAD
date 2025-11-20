<#
Restrict ESC1/ESC2 by locking down enrollment permissions.
#>
param(
    [string]$TemplateName = "User",
    [string]$AllowedGroup = "PKI_Enrollment"
)

$template = Get-CATemplate -Name $TemplateName
Write-Host "[+] Removing Authenticated Users from $TemplateName enrollment"
$template.Permissions | Where-Object {$_.Principal -eq "Authenticated Users"} | ForEach-Object {
    $_.Rights = $_.Rights -bxor "Enroll"
}
$ace = New-Object -TypeName Microsoft.CertificateServices.Commands.CertificateTemplatePermission -Property @{Principal=$AllowedGroup; Rights="Enroll"}
$template.Permissions.Add($ace)
$template | Set-CATemplate
Write-Host "[+] Enrollment locked to $AllowedGroup"
