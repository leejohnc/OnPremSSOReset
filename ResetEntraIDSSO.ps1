 <#
Author:  John Lee
Created:  8/20/21
Updated:  12/19/23
Version:  1.1.0

Revisions: 1.0.0 Initial version
Update:    1.1.0 Moved vars into Azure Automation variables
pre-req's
*The domain controller must be in an Azure IaaS OR have the Azure ARC agent installed as it will be used as the
 hybrid worker.

*The domain controller must be able to run Azure Automation scripts, so its agent must be present in Azure Automation
 ADConnect .dll's from c:\program files\Microsoft Azure Active Directory Connect must be copied to the same location on
 the domain controller where Azure Automation will run the script.

*There must be an on-prem service account in the TIER 0 OU.
*The on-prem account should be restricted to the domain controller.
*There must be an Entra ID User account, set up as eligible in PIM for the Hybrid Identity Administrator Role
*The cloud account should be contrained by conditional access to only be usable from the domain controller, and
 not permit logon from any other location.

*This script will download any PowerShell dependencies to the Domain Controller.
*Ensure the Azure Automation account where this will be running is in a TIER 0 sub that is only readable and manageable by global admins.
 Remember what you are dealing with here.

* Set your azure automation variables, see lines 201 through 205

This script will check the AzureAD KrbTGT (used for Windows Hello) and the Azure Hybrid SSO computer object's last password
date.  If older than 30 days:

The script will logon with an AzureAD user, that is restricted by a conditional access policy, on the Azure Automation enabled
domain controller.

That user will then evalate to the AzureAD Hybrid Identity Role, create a temporary Domain Admin/Enterprise Admin with 
a random password

Reset both the SSO object and AzureAD KrbTGT passwords, the remove the temprorary Domain Admin/Enterprise Admin from those groups,
randomize the password, and disable the temp account

The actions will be sent via email, alerting on the state the resets are (failed, succeeded).

#>

########################################################################
#Functions Region
#Do not make changes to functions
########################################################################
#region functions
#Microsoft's check a generated complicated password to make sure it's complicated
function Confirm-CtmADPasswordIsComplex{
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string]
    $Pw
    )
        Process
        {
        $CriteriaMet = 0
        If ($Pw -cmatch '[A-Z]') {$CriteriaMet++}
        If ($Pw -cmatch '[a-z]') {$CriteriaMet++}
        If ($Pw -match '\d') {$CriteriaMet++}
        If ($Pw -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$CriteriaMet++}
        If ($CriteriaMet -lt 3) {Return $false}
        If ($Pw.Length -lt 6) {Return $false}
        Return $true
        }
    }

#generate complex password
function New-CtmADComplexPassword{
    Param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [ValidateRange(6,127)]
        [Int]
        $PwLength=24
    )
    Process
        {
        $Iterations = 0
        Do
            {
            If ($Iterations -ge 20)
                {
                Write-Error   "Password generation failed to meet complexity after $Iterations attempts, exiting."
                Return $null
                }
            $Iterations++
            $PWBytes = @()
            $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            Do
                {
                [byte[]]$Byte = [byte]1
                $RNG.GetBytes($Byte)
                If ($Byte[0] -lt 33 -or $Byte[0] -gt 126) { continue }
                $PWBytes += $Byte[0]
                }
            While
                ($PWBytes.Count -lt $PwLength)
 
            $Pw = ([char[]]$PWBytes) -join ''
            }
        Until
            (Confirm-CtmADPasswordIsComplex $Pw)
        Return $Pw
        }     
    }

#use PIM to elevate the Admin user
Function Grant-EntraHybridAdmin ([System.Management.Automation.PSCredential]$AzureADCredential){
    Write-output "Attempting to elevate to Role: Azure AD Hyrbid Identity Administrator"
    try{
    Write-output "Attempting to connect to Azure AD"
    Connect-AzureAD -Credential $AzureADCredential -ErrorAction SilentlyContinue -ErrorVariable noConnect
    }
    catch{
    Write-Error "Failed to connect to Azure AD.  Exiting"
    Return $noConnect} 

    #cannot use connect-mggraph because it won't accept anything but interactive logons and app registrations
    #cannot use get-azaccesstoken because that will not accept specified scopes
    #thanks Microsoft
    Write-output "Connected to Azure AD"

    try{
    if(!(Get-InstalledModule -Name AzureADPreview)){
    Write-output "AzureADPreview module not found, installing..."
    Install-Module -Name AzureADPreview -RequiredVersion 2.0.2.149 -AllowClobber}
    Import-Module AzureADPreview -RequiredVersion 2.0.2.149

    Write-output "Getting AzureAD Tenant details"
    $tenantID=Get-AzureADTenantDetail
    
    Write-output "Getting AzureAD privileged role definition for Hybrid Identity Administrator "
    $AADRole=Get-AzureADMSPrivilegedRoleDefinition -ProviderId aadRoles `
                                                   -ResourceId $tenantID.ObjectID `
                                                   -Filter "endswith(DisplayName,'Hybrid Identity Administrator')"
    
  
    Write-output "AzureAD Credential to be elevated: $($AzureADCredential.UserName)"
    $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
    $schedule.Type = "Once"
    $schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $schedule.endDateTime =(( get-date ).AddHours(1)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    
    $AdmUserID=Get-AzureADUser -Filter "userprincipalname eq '$($AzureADCredential.UserName)'"
    
    $ActiveGAAssignment=Get-AzureADMSPrivilegedRoleAssignment -ProviderId "aadRoles" `
                                                              -ResourceId "$($tenantID.ObjectID)" `
                                                              -Filter "subjectId eq '$($AdmUserID.ObjectId)' and RoleDefinitionId eq '$($AADRole.ID)' and AssignmentState eq 'Eligible'"
    if(!$ActiveGAAssignment)
    {
    Write-output "An active elevation already exists for: $($AzureADCredential.UserName)"
    break}
    
    Write-output "Elevating: $($AzureADCredential.UserName)"
    Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId 'aadRoles' `
                                                  -ResourceId "$($tenantID.ObjectID)" `
                                                  -RoleDefinitionId "$($AADRole.ID)" `
                                                  -SubjectId "$($AdmUserID.ObjectId)" `
                                                  -Type 'userAdd' `
                                                  -AssignmentState 'Active' `
                                                  -Schedule $schedule `
                                                  -Reason "Resetting Hybrid SSO and AzureAD KrbTGT"
    
    sleep -Seconds 30 
    Return $true
                                                    
    }
    catch{Return $false}
}

#add specified user to specified group, check membership fist
Function Add-PrivGripMember ([STRING]$group,[STRING]$user){
if(!((Get-ADGroup -Identity $group -Properties member).member -replace "(CN=)(.*?),.*",'$2' | Where-Object {$_ -eq "$($user)"})){ 
Write-output "Add $($user) to $group"
Add-ADGroupMember -Identity $group -Members "$($user)" -Confirm:$false 
 }
}

#remove specified user to specified group, check membership fist
Function Remove-PrivGripMember ([STRING]$group,[STRING]$user){
if(((Get-ADGroup -Identity $group -Properties member).member -replace "(CN=)(.*?),.*",'$2' | Where-Object {$_ -eq "$($user)"})){ 
Write-output "remove $($user) from $group"
Remove-ADGroupMember -Identity $group -Members "$($user)" -Confirm:$false 
 }
} 

Function Grant-ADAccountAccess([STRING]$ADuserName,[STRING]$DC){
Write-output "Enable user: $($(($ADuserName) -split "\\")[1])"
    Enable-ADAccount -Identity $(($ADuserName) -split "\\")[1] -Server $dc
    Add-PrivGripMember -group "Domain Admins"     -user $(($ADuserName) -split "\\")[1]
    Add-PrivGripMember -group "Enterprise Admins" -user $(($ADuserName) -split "\\")[1] 
}

Function Revoke-ADAccountAccess([STRING]$ADuserName,[STRING]$ADuserPassword,[STRING]$DC){
    $Newpassword = (ConvertTo-SecureString -AsPlainText $ADuserPassword  -Force)
    Write-output "Scramble user password for: $($(($ADuserName) -split "\\")[1])"
    Set-ADAccountPassword -Identity $(($ADuserName) -split "\\")[1] -NewPassword $Newpassword -Server $DC
    Write-output "Disable user: $($(($ADuserName) -split "\\")[1])"
    Disable-ADAccount -Identity $(($ADuserName) -split "\\")[1] -Server $dc

    Remove-PrivGripMember -group "Domain Admins"     -user $(($ADuserName) -split "\\")[1]
    Remove-PrivGripMember -group "Enterprise Admins" -user $(($ADuserName) -split "\\")[1]
    try{
    Write-output "Disconnect AzureAD session"
    Disconnect-AzureAD -Confirm:$false -ErrorAction SilentlyContinue}
    catch{}
}

#endregion
########################################################################
#End Functions Region
########################################################################



#region vars that you should set
$senderAcct = Get-AutomationVariable -Name "AzureJobSender"
$recipient  = Get-AutomationVariable -Name "AzureJobFailureAlertList"
$SMTPRelay  = Get-AutomationVariable -Name "OnPremSMTPRelay"
$tenant     = Get-AutomationVariable -Name "AzureTenantName"
$ADSrvAcct  = Get-AutomationVariable -Name "OnPremADServiceAccount"

$domain     = Get-ADDomain
$DC         = $(hostname)
$MaxAge     = 30

########################################################################
#Do not make changes belows this line
########################################################################
#grab the AzureAD SSO user cred for Azure Automation
Write-output "Retrieving AzureAD SSO Automation Creds"
$AzureADSSO = get-automationPSCredential -Name "AzureADSSO"


#set the location for ADConnect's DLL files, then import the module
Write-output "Loading AzureAD Connect Modules"
$loc        = "$env:ProgramFiles\Microsoft Azure Active Directory Connect"
Import-Module $loc\AzureADSSO.psd1


#set the TLS level that the script will be using
Write-output "Setting TLS to v1.2"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#set the on-prem crendential with a new random password
Write-output "Setting the temporary on-prem credential password"
[string]$ADuserName     = "$($domain.NetBIOSName)\$($ADSrvAcct)"
[string]$ADuserPassword = New-CtmADComplexPassword -PwLength 50

$Newpassword = (ConvertTo-SecureString -AsPlainText $ADuserPassword  -Force)
Set-ADAccountPassword -Identity $(($ADuserName) -split "\\")[1] -NewPassword $Newpassword -Server $DC
    
# Convert to SecureString
[securestring]$ADsecStringPassword = ConvertTo-SecureString $ADuserPassword -AsPlainText -Force
[pscredential]$ADcreds             = New-Object System.Management.Automation.PSCredential ($ADuserName, $ADsecStringPassword)

#set the current data var
$today=Get-date

#Check the last password value of the AzureAD SSO object in on-prem AD

$AzureADSSOObject=Get-date((Get-ADComputer AZUREADSSOACC -Properties passwordlastset).passwordlastset)
$diff=(New-TimeSpan -Start $AzureADSSOObject -End $today).Days
Write-output "Azure AD SSO object is $($diff) days old."
#if the AzureAD SSO object's password is older then 30 days, reset it.  
if($diff -ge $MaxAge){
    Write-output "Resetting Azure AD SSO object"
    #call the custom function to enable the on-prem temporary account
    #and put that account in domain admins and enterprise admins
    Grant-ADAccountAccess -ADuserName $ADuserName -DC $dc

    #call the custom function to elevate the AzureAD user to the Hybrid Identity Administrator Role
    $Elevation=Grant-EntraHybridAdmin -AzureADCredential $AzureADSSO
    if(!$Elevation){break}

    #reset AzureAD Hybrid SSO for on-prem AD
    try{
        #set the context for resetting the SSO object
        

        Write-output "Set Azure AD authentication context for $($tenant)."
        #will not accept the use of app registration with secrets or certs
        #cannot use MSAL.PS tokens
        #stuck with manual resets or stored creds
        #thanks Microsoft
        New-AzureADSSOAuthenticationContext -CloudCredentials $AzureADSSO -TenantId $tenant -Verbose #ask for Azure Global Admin
        
        Get-AzureADSSOStatus -Verbose | ConvertFrom-Json -Verbose #ask for onprem DA account
        
        #Reset the SSO Object
        Write-output "Update Azure AD SSO Passord $($tenant)."
        Update-AzureADSSOForest -OnPremCredentials $ADcreds -PreserveCustomPermissionsOnDesktopSsoAccount -Verbose
    }
    catch{
            
            #if the attempt fails, remove the temp admin from domain admins and enterprise admins
            #scramble the password, and disable the account
            Write-error "Update Azure AD SSO Passord for $($tenant) failed."
            Revoke-ADAccountAccess -ADuserName $ADuserName -ADuserPassword $ADuserPassword -DC $dc
            
            
            #send an email that the attempt failed, and stop the script
            Write-output "Sending Azure AD SSO update failure email to team."
            $body="AzureAD Hybrid SSO Reset failed for $($domain.NetBIOSName)"
                   
            Send-MailMessage -From $senderAcct `
                             -to  $recipient `
                             -Subject "FAILED: $($domain.NetBIOSName) AzureAD Hybrid SSO Reset" `
                             -Body $body `
                             -Priority High `
                             -BodyAsHtml `
                             -SmtpServer $SMTPRelay `
                             -Port 25
            #stop the script
            break
    
    }
    #the attempt succeeded, send an email
    Write-output "Update Azure AD SSO Passord for $($tenant) succeeded, sending email to team."
    $body="AzureAD Hybrid SSO Reset succeeded for $($domain.NetBIOSName)"
           
    Send-MailMessage -From $senderAcct `
                     -to  $recipient `
                     -Subject "SUCCESS: $($domain.NetBIOSName) AzureAD Hybrid SSO Reset" `
                     -Body $body `
                     -Priority High `
                     -BodyAsHtml `
                     -SmtpServer $SMTPRelay `
                     -Port 25
    
}

#check the AzureAD KrbTGT
$AzureADKrbTGT=Get-date((Get-ADUser -filter {cn -eq "krbtgt_AzureAD"} -Properties passwordlastset).passwordlastset)
$diff=(New-TimeSpan -Start $AzureADKrbTGT -End $today).Days
Write-output "Azure AD Windows Hello Cloud trust Passord for $($tenant) is $($diff) days old."

#if the AzureAD KrbTGT is older than 30 days, reset it
if($diff -ge $MaxAge){
   Write-output "Azure AD Windows Hello Cloud trust Passord is being reset."
    #Elevete, if the temp accouunt needs to enabled and elevated to domain admin/enterprise admin
    Grant-ADAccountAccess -ADuserName $ADuserName -DC $dc
    
    #if the AzureAD SSO account is not already elevated from the SSO reset in the previous step - then do it in this step
    if(!$Elevation){$Elevation=Grant-EntraHybridAdmin -AzureADCredential $AzureADSSO}
    # if the elevation has not happend, stop the script
    if(!$Elevation){break}

    # install the Hybrid auth module, if it's not present

    if(!(Get-Module -name AzureADHybridAuthenticationManagement)){
    Write-output "Azure AD Hybrid Auth PowerShell module is not present.  Installing the module"
    Install-Module -Name AzureADHybridAuthenticationManagement -AllowClobber
    }
   
    Try{
         #Set the AzureAD KrbTGT
         Write-output "Attempting to set Azure AD Cloud Trust password"
         Set-AzureADKerberosServer -Domain $($domain.DNSRoot) -DomainCredential $ADCreds -CloudCredential $AzureADSSO  -RotateServerKey
    }
    catch{
            #if the attempt fails, remove the temp admin from domain admins and enterprise admins
            #scramble the password, and disable the account
             Write-error "Attempting to set Azure AD Cloud Trust password failed."
             Revoke-ADAccountAccess -ADuserName $ADuserName -ADuserPassword $ADuserPassword -DC $dc

            
            #send an email that the attempt failed, and stop the script
            Write-output "Sending Azure AD Cloud Trust password failed message to team."
            $body="AzureAD Cloud KrbTGT Reset failed for $($domain.NetBIOSName)"
                   
            Send-MailMessage -From $senderAcct `
                             -to  $recipient `
                             -Subject "Failed: $($domain.NetBIOSName) AzureAD Cloud KrbTGT Reset " `
                             -Body $body `
                             -Priority High `
                             -BodyAsHtml `
                             -SmtpServer $SMTPRelay `
                             -Port 25
            #stop the script
            break
    }
    #the attempt succeeded, send an email
    Write-output "Attempting to set Azure AD Cloud Trust password succeeded.  Sending email"
    $body="AzureAD Cloud KrbTGT Reset succeeded for $($domain.NetBIOSName)"
           
    Send-MailMessage -From $senderAcct `
                     -to  $recipient `
                     -Subject "SUCCESS: $($domain.NetBIOSName) AzureAD Cloud KrbTGT Reset" `
                     -Body $body `
                     -Priority High `
                     -BodyAsHtml `
                     -SmtpServer $SMTPRelay `
                     -Port 25
  
}
#Remove the temp admin from domain admins and enterprise admins
#scramble the password, and disable the account
Revoke-ADAccountAccess -ADuserName $ADuserName -ADuserPassword $ADuserPassword -DC $dc 
