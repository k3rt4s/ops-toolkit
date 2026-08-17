#Requires -Modules Pester

# Unit coverage over the three grading functions.
#
# These matter more than usual for this script, because the case they protect cannot
# be produced on the machine the suite runs on. Every path where a reading is null,
# meaning audit policy or the Security log could not be read, only occurs in an
# unelevated session, and the validation suite is normally run elevated. If those
# paths are wrong the script reports a clean posture for a machine it never read,
# which is the exact failure it exists to prevent, and no live run here would show it.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Import-ReportingModule
    Import-ScriptFunction -RelativePath 'scripts\logging\Export-EndpointTelemetryPosture.ps1' `
        -FunctionName @('Get-TelemetryCheckStatus', 'Get-RetentionStatus', 'Get-MachineTelemetryVerdict', 'Add-TelemetryCheck')
}

Describe 'Get-TelemetryCheckStatus' {
    It 'reports an unreadable required setting as Undetermined, not as disabled' {
        # The whole point. An unelevated run cannot read audit policy, and grading that
        # as Disabled would produce a report full of confident findings about settings
        # nobody looked at.
        Get-TelemetryCheckStatus -Actual $null -Requirement 'Required' -Enabled $null | Should -Be 'Undetermined'
    }

    It 'reports an unreadable recommended setting as Undetermined too' {
        Get-TelemetryCheckStatus -Actual $null -Requirement 'Recommended' -Enabled $null | Should -Be 'Undetermined'
    }

    It 'does not treat a value that was read as unreadable just because it is off' {
        # 'No Auditing' is a successful read of a subcategory that is switched off.
        Get-TelemetryCheckStatus -Actual 'No Auditing' -Requirement 'Required' -Enabled $false | Should -Be 'Disabled'
    }

    It 'reports an enabled setting as Enabled' {
        Get-TelemetryCheckStatus -Actual 'Success and Failure' -Requirement 'Required' -Enabled $true | Should -Be 'Enabled'
    }

    It 'treats an absent conditional item as a known absence rather than a failed read' {
        # Sysmon not being installed is a fact, not a gap. An estate that does not run
        # it must not be reported as having a hole where it would be.
        Get-TelemetryCheckStatus -Actual $null -Requirement 'Conditional' -Enabled $null | Should -Be 'NotRequired'
    }

    It 'does not count a conditional item that is off as a gap' {
        Get-TelemetryCheckStatus -Actual '' -Requirement 'Conditional' -Enabled $false | Should -Be 'NotRequired'
    }

    It 'still reports a conditional item that is on as Enabled' {
        Get-TelemetryCheckStatus -Actual 'Running' -Requirement 'Conditional' -Enabled $true | Should -Be 'Enabled'
    }

    It 'returns only the four defined outcomes' {
        $seen = foreach ($requirement in @('Required', 'Recommended', 'Conditional')) {
            foreach ($enabled in @($true, $false, $null)) {
                Get-TelemetryCheckStatus -Actual 'x' -Requirement $requirement -Enabled $enabled
            }
        }
        @($seen).Count | Should -Be 9
        foreach ($status in $seen) {
            $status | Should -BeIn @('Enabled', 'Disabled', 'NotRequired', 'Undetermined')
        }
    }
}

Describe 'Get-RetentionStatus' {
    It 'reports an unmeasurable channel as Unmeasured rather than sufficient' {
        # A channel with no records returns no oldest timestamp. Grading that as
        # Sufficient would say an empty log covers 30 days.
        Get-RetentionStatus -RetentionDays $null -MinimumDays 30 -IsFull $true | Should -Be 'Unmeasured'
    }

    It 'reports retention at or above the minimum as Sufficient' {
        Get-RetentionStatus -RetentionDays 30 -MinimumDays 30 -IsFull $true | Should -Be 'Sufficient'
        Get-RetentionStatus -RetentionDays 110.5 -MinimumDays 30 -IsFull $true | Should -Be 'Sufficient'
    }

    It 'reports a full channel below the minimum as Insufficient' {
        # This is the finding that matters: the log is full and rolling, so six hours
        # of history is all there will ever be.
        Get-RetentionStatus -RetentionDays 0.3 -MinimumDays 30 -IsFull $true | Should -Be 'Insufficient'
    }

    It 'separates a young channel from an overwriting one' {
        # A machine built three days ago holds three days of logs and is not
        # misconfigured. Reporting it as Insufficient trains the operator to ignore
        # the status.
        Get-RetentionStatus -RetentionDays 3 -MinimumDays 30 -IsFull $false | Should -Be 'Building'
    }

    It 'assumes the unfavourable case when fullness is unknown' {
        # Unknown fullness is treated as full. Assuming the generous case is how a
        # rolling log gets reported as fine.
        Get-RetentionStatus -RetentionDays 3 -MinimumDays 30 -IsFull $null | Should -Be 'Insufficient'
    }
}

Describe 'Get-MachineTelemetryVerdict' {
    It 'reports a machine with no checks as Undetermined, not Covered' {
        # Zero gaps across zero checks is a run that read nothing. Every previous bug
        # of this shape in this repo looked like good news.
        Get-MachineTelemetryVerdict -DisabledCount 0 -UndeterminedCount 0 -InsufficientCount 0 -CheckedCount 0 |
            Should -Be 'Undetermined'
    }

    It 'lets Undetermined outrank a clean result' {
        Get-MachineTelemetryVerdict -DisabledCount 0 -UndeterminedCount 1 -InsufficientCount 0 -CheckedCount 20 |
            Should -Be 'Undetermined'
    }

    It 'lets Undetermined outrank a partial result' {
        # A machine with two known gaps and one unread setting is Undetermined. The
        # unread one could be the worst of the three, and presenting the known subset
        # as the whole picture is the failure mode this script is built against.
        Get-MachineTelemetryVerdict -DisabledCount 2 -UndeterminedCount 1 -InsufficientCount 0 -CheckedCount 20 |
            Should -Be 'Undetermined'
    }

    It 'reports a fully read clean machine as Covered' {
        Get-MachineTelemetryVerdict -DisabledCount 0 -UndeterminedCount 0 -InsufficientCount 0 -CheckedCount 20 |
            Should -Be 'Covered'
    }

    It 'does not report a machine with insufficient retention as Covered' {
        # Logging switched on but rolling over in hours is not coverage.
        Get-MachineTelemetryVerdict -DisabledCount 0 -UndeterminedCount 0 -InsufficientCount 2 -CheckedCount 20 |
            Should -Be 'Partial'
    }

    It 'reports a machine with everything off as NotCovered' {
        Get-MachineTelemetryVerdict -DisabledCount 20 -UndeterminedCount 0 -InsufficientCount 0 -CheckedCount 20 |
            Should -Be 'NotCovered'
    }
}

Describe 'Add-TelemetryCheck' {
    It 'appends a graded record carrying the reason the setting matters' {
        $records = [System.Collections.Generic.List[object]]::new()
        Add-TelemetryCheck -Record $records -ComputerName 'PC01' -Category 'PowerShell' `
            -Setting 'Script block logging' -Actual 0 -Enabled $false -Requirement 'Required' `
            -Why 'Event 4104 is the only record of what a fileless payload ran.' -Detail 'Enable the policy.'

        $records.Count | Should -Be 1
        $records[0].Status | Should -Be 'Disabled'
        $records[0].ComputerName | Should -Be 'PC01'
        # A status with no reason cannot be acted on by whoever reads the CSV.
        $records[0].Why | Should -Not -BeNullOrEmpty
        $records[0].Detail | Should -Not -BeNullOrEmpty
    }

    It 'flattens an array reading into a single cell rather than a type name' {
        $records = [System.Collections.Generic.List[object]]::new()
        Add-TelemetryCheck -Record $records -ComputerName 'PC01' -Category 'Forwarding' `
            -Setting 'Event forwarding subscription manager' -Actual @('http://a', 'http://b') `
            -Enabled $true -Requirement 'Conditional' -Why 'Local logs die with the machine.'

        $records[0].Actual | Should -Be 'http://a;http://b'
    }

    It 'carries an unreadable setting through as Undetermined' {
        $records = [System.Collections.Generic.List[object]]::new()
        Add-TelemetryCheck -Record $records -ComputerName 'PC01' -Category 'AuditPolicy' `
            -Setting 'Process Creation' -Actual $null -Enabled $null -Requirement 'Required' `
            -Why 'No 4688 means no record of what ran.'

        $records[0].Status | Should -Be 'Undetermined'
    }
}
