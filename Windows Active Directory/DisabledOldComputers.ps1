# === AI REVIEWER - READ BEFORE EDITING ==============================
# Before changing this file, read the master workspace README at
#   d:\Proton Drive\My files\Code\README.md   ("AI Session Rules" section)
# and the README(s) for this project and sub-product. Those documents
# are the single source of truth for venvs, path conventions,
# archive/backup rules, markdown conventions, and every repo-wide rule.
# Do not guess - reference the READMEs first.
# =====================================================================

# This PowerShell Command will query Active Directory and return the computer accounts which have not logged for the past
# 30 days.  You can easily change the number of days from 30 to any number of your choosing. After, the computers will be
# moved to the "DisabledComputers" OU

# Email notification will be sent to techops@example.com

# Note: This script needs to be run with administrator priviledges.
#       If script is not run with administrator priviledges,
#       Get-QADUser function will not return PasswordExpires and PwdLastSetattributes correctly.
#
#       You might need to sign the powershell script so that it can run inbatch mode (as opposed to interactive mode).
#       To do that, you will need to run elevated command prompt, runpowershell (by typing powershell on the command prompt),
#       next, type "set-executionpolicy RemoteSigned" (without the doublequotes) on the powershell prompt.



#####################
# Variables to change
#####################

# Time
$LL = (Get-Date).AddDays(-30)

# SMTP Server to be used
$smtp = "192.0.2.230"

# "From" address of the email
$from = "OldCorpComputers@example.com"

# Administrator email
$admin = "techops@example.com"

# Web address of your OWA url - tested only with Exchange 2007 SP2
$OWAURL = "mailsvr.example.com"

# First name of administrator
$AdminName = "Techops"

# Define font and font size
# ` or \ is an escape character in powershell
$font = "<font size=`"3`" face=`"Calibri`">"



##########################################
# Should require no change below this line
# (Except message body)
##########################################

# AD List for computers older than $LL 
Get-ADComputer -Property Name,lastLogonDate -Filter {lastLogonDate -lt $LL} | FT Name,lastLogonDate

# AD Output for computers older than $LL
$string = Get-ADComputer -Property Name,lastLogonDate -Filter {(enabled -eq "true") -and (lastLogonDate -lt $LL)} -ResultSetSize $null | Select-Object Name, LastLogonDate | Sort-Object -property name | ConvertTo-Html -fragment | Out-string

# Disable computers older than $LL
Get-ADComputer -Property Name,lastLogonDate -Filter {(enabled -eq "true") -and (lastLogonDate -lt $LL)} | Set-ADComputer -Enabled $false

# Move computers older than $LL to the "DisabledComputers" OU
Get-ADComputer -Property Name,lastLogonDate -Filter {(enabled -eq "true") -and (lastLogonDate -lt $LL)} | Move-ADObject -TargetPath "OU=DisabledComputers,DC=example,DC=local"

# If you would like to Remove these computer accounts, uncomment the following line:
# Get-ADComputer -Property Name,lastLogonDate -Filter {(enabled -eq "true") -and (lastLogonDate -lt $LL)} | Remove-ADComputer

# Send Email to Techops
function Send-Mail{
param($smtpServer,$from,$to,$subject,$body)
$smtp = new-object system.net.mail.smtpClient($SmtpServer)
$mail = new-object System.Net.Mail.MailMessage
$mail.from = $from
$mail.to.add($to)
$mail.subject = $subject
$mail.body = $body
# Send email in HTML format
$mail.IsBodyHtml = $true
$smtp.send($mail)

}

# Newline character
#$newline = [char]13+[char]10
$newline = "<br>"

# Get today's day, date and time
$today = (Get-date)

# Loads the Quest.ActiveRoles.ADManagement snapin required for thescript.
# (Will unload once powershell is exited)
add-pssnapin "Quest.ActiveRoles.ADManagement"

# If there are computers than have not Logged in within $LL
# Email notification to administrator
$to = $admin
$subject = "Disabled Corp Computers $today"

                # Message body is in HTML font          
                $body = $font
                $body += "Dear Administrators,"
				$body += $newline
				$body += $newline
				$body += " The following computer accounts have been disabled as of $today."
				$body += $newline
				$body += " Please contact Info Sec at infosec@example.com if computers have been disabled in error."
				$body += $newline
				$body += $newline
				$body += $string
				
				
                # Put a timestamp on the email
                $body += $newline + $newline + $newline + $newline
                $body += "<h5>Message generated on: " + $today + ".</h5>"
                $body += "</font>"

                # Invokes the Send-Mail function to send notification email
                Send-Mail -smtpServer $smtp -from $from -to $to -subject $subject -body $body


# End of script 
