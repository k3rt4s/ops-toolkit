# === AI REVIEWER - READ BEFORE EDITING ==============================
# Before changing this file, read the master workspace README at
#   d:\Proton Drive\My files\Code\README.md   ("AI Session Rules" section)
# and the README(s) for this project and sub-product. Those documents
# are the single source of truth for venvs, path conventions,
# archive/backup rules, markdown conventions, and every repo-wide rule.
# Do not guess - reference the READMEs first.
# =====================================================================

#    Copyright 2009 Dan Penning
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Start of script
# ExpiringPasswords.ps1
# 12/30/2009
#
#
# Purpose:
# Powershell script to find out a list of users
# whose password is expiring within x number of days (as specified in $days_before_expiry).
# Email notification will be sent to them reminding them that they need to change their password.
#
# Requirements:
# ExpiringPasswords.ps1 is dependant on Quest.ActiveRoles.ADManagementsnapin to get the AD attributes.
# The Quest.ActiveRoles.ADManagement snapin can be downloaded from'PowerShell Commands (CMDLETs) for Active Directory by Quest Software'(http://www.quest.com/powershell/activeroles-server.aspx)
# Look for ActiveRoles Management Shell for Active Directory (both32-bit or 64-bit versions available)
# Also available in P:\Software\Microsoft\Windows Powershell snap-in.
#
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

# Days to Password Expiry
$days_before_expiry = 7

# SMTP Server to be used
$smtp = "Server"

# "From" address of the email
$from = "Email@domain.com"

# Administrator email
$admin = "Email@domain.com"

# Web address of your OWA url - tested only with Exchange 2007 SP2
$OWAURL = "OWA URL"

# First name of administrator
$AdminName = "Name"

# Define font and font size
# ` or \ is an escape character in powershell
$font = "<font size=`"3`" face=`"Calibri`">"


##########################################
# Should require no change below this line
# (Except message body)
##########################################

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

# Retrieves list of users whose account is enabled, has a passwordexpiry date and whose password expiry date within (is less than) today+$days_before_expiry
$users_to_be_notified = Get-QADUser -Enabled -passwordNeverExpires:$False | Where {($_.PasswordExpires -lt
$today.AddDays($days_before_expiry))}

# Send email to notify users
foreach ($user in $users_to_be_notified) {

# Calculate the remaining days
# If result is negative, then it means password has already expired.
# If result is positive, then it means password is expiring soon.
$days_remaining = ($user.PasswordExpires - $today).days

        # Set font for HTML message
        $body = $font

        # For users whose password already expired
        if ($days_remaining -le 0) {

                # Make the days remaining positive (because we are reporting it as expired)
                $days_remaining = [math]::abs($days_remaining)

                # Add it in a list (to be sent to admin)
                $expired_users += $user.name + " - <font color=blue>" + $user.LogonName + "</font>'s password has expired <font color=blue>" + $days_remaining + "</font> day(s) ago." + $newline

                # If there is an email attached to profile
                if ($user.Email -ne $null) {

                        # Email notification to user
                        $to = $user.Email
                        $subject = "Reminder - Password has expired " + $days_remaining + "day(s) ago."

                        # Message body is in HTML font
                        $body += "Dear " + $user.givenname + "," + $newline + $newline
                        $body += "This is a friendly reminder that your password for account'<font color=blue>" + $user.LogonName + "</font>' has already expired "+ $days_remaining + " day(s) ago."
                        $body += " Please contact the systems administrator to arrange for your password to be reset."
                        }
                else {

                        # Email notification to administrator
                        $to = $admin
                        $subject = "Reminder - " + $user.LogonName+ "'s Password has expired" + $days_remaining + " day(s) ago."

                        # Message body is in HTML font
                        $body += "Dear administrator," + $newline + $newline
                        $body += "<font color=blue>" + $user.LogonName+ "</font>'s password has expired <font color=blue>" + $days_remaining + " day(s) ago</font>."
                        $body += " However, the system has detected that there is no email address attached to the profile."
                        $body += " Therefore, no email notifications has been sent to " + $user.Name + "."
                        $body += " Kindly reset the password and notify user of the password change."
                        $body += " In addition, please add a corresponding email address to the profile so emails can be sent directly for future notifications."
                        }

                # Put a timestamp on the email
                $body += $newline + $newline + $newline + $newline
                $body += "<h5>Message generated on: " + $today + ".</h5>"
                $body += "</font>"

                # Invokes the Send-Mail function to send notification email
		# Comment out this line if you do not want to send email to users with already expired passwords.
                Send-Mail -smtpServer $smtp -from $from -to $to -subject $subject-body $body
        }

        # For users whose password is expiring
        # if ($days_remaining -gt 0) {
        else {

                # Add it in a list (to be sent to admin)
                $expiring_users += $user.name + " - <font color=blue>" +$user.LogonName + "</font> has <font color=blue>" + $days_remaining +"</font> day(s) remaing left to change his/her password." + $newline

                # If there is an email attached to profile
                if ($user.Email -ne $null) {

                        # Email notification to user
                        $to = $user.Email
                        $subject = "Reminder - Password is expiring in " + $days_remaining +" day(s)."

                        # Message body is in HTML font
                        $body += "Dear " + $user.givenname + "," + $newline + $newline
                        $body += "This is a friendly reminder that your password for account '<font color=blue>" + $user.LogonName + "</font>' is due to expire in "+ $days_remaining + " day(s)."
						$body += "You can reset your password by visiting <a href=https://mailsvr.example.com/ecp/?rfr=owa&p=PersonalSettings/Password.aspx</a> and completing the form."
                        $body += " Please remember to change your password before <fontcolor=blue>" + $user.PasswordExpires.date.tostring('MM/dd/yyyy') +"</font>."
                        }
                else {

                        # Email notification to administrator
                        $to = $admin
                        $subject = "Reminder - " + $user.LogonName+ "'s Password is expiringin " + $days_remaining + " day(s)."

                        # Message body is in HTML font
                        $body += "Dear administrator," + $newline + $newline
                        $body += "<font color=blue>" + $user.LogonName+ "</font>'s password is expiring in <font color=blue>" + $days_remaining + " day(s)</font>."
                        $body += " However, the system has detected that there is no email address attached to the profile."
                        $body += " Therefore, no email notifications has been sent to " +$user.Name + "."
                        $body += " Kindly remind him/her to change the password before <fontcolor=blue>" + $user.PasswordExpires.date.tostring('dd/MM/yyyy') +"</font>."
                        $body += " In addition, please add a corresponding email address to the profile so emails can be sent directly for future notifications."
                        }

                # Put a timestamp on the email
                $body += $newline + $newline + $newline + $newline
                $body += "<h5>Message generated on: " + $today + ".</h5>"
                $body += "</font>"

                # Invokes the Send-Mail function to send notification email
                Send-Mail -smtpServer $smtp -from $from -to $to -subject $subject -body $body
        }

}

# If there are users with expired password or users whose password is
expiring soon
if ($expired_users -ne $null -and $expiring_users -ne $null) {

                # Email notification to administrator
                $to = $admin
                $subject = "Password Expiry Report"

                # Message body is in HTML font          
                $body = $font
                $body += "Dear " + $AdminName + ","+ $newline + $newline
                $body += "The following users' passwords are expiring soon or have already expired." + $newline + $newline + $newline
                $body += "<b>Users with expired passwords:</b>" + $newline
                $body += $expired_users + $newline + $newline
                $body += "<b>Users with passwords expiring soon:</b>" + $newline
                $body += $expiring_users

                # Put a timestamp on the email
                $body += $newline + $newline + $newline + $newline
                $body += "<h5>Message generated on: " + $today + ".</h5>"
                $body += "</font>"

                # Invokes the Send-Mail function to send notification email
                Send-Mail -smtpServer $smtp -from $from -to $to -subject $subject -body $body

}

# End of script 
