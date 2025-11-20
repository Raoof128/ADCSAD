<#
Removes dangerous EKUs from templates and enforces least privilege.
#>
param(
    [string]$TemplateName = "User"
)

Write-Host "[+] Auditing EKUs for template $TemplateName"
$template = Get-CATemplate -Name $TemplateName
if($template.EnhancedKeyUsage -contains "CertificateRequestAgent" -or $template.EnhancedKeyUsage -contains "AnyPurpose"){
    Write-Host "[-] Dangerous EKU detected. Removing..."
    $template.EnhancedKeyUsage = $template.EnhancedKeyUsage | Where-Object {$_ -notin @("CertificateRequestAgent","AnyPurpose","ClientAuth")}
    $template | Set-CATemplate
    Write-Host "[+] EKUs sanitized"
}else{
    Write-Host "[+] No dangerous EKUs found"
}
