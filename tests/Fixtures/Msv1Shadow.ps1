# Dot-sourced into a child process by the NTLM tests: answers reads of the MSV1_0 key from the table
# in OPSTOOLKIT_TEST_MSV1 ('Name=1;Other=2', or 'none' for a key with no values) and passes every other
# path to the real Get-Item, so no assertion depends on the machine the suite runs on.
function Get-Item {
    [CmdletBinding()]
    param([string]$Path, [string]$LiteralPath)
    $target = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($target -like '*\Control\Lsa\MSV1_0') {
        $table = @{}
        foreach ($pair in ($env:OPSTOOLKIT_TEST_MSV1 -split ';')) { if ($pair -match '^(\w+)=(\d+)$') { $table[$Matches[1]] = [int]$Matches[2] } }
        $key = [pscustomobject]@{ Table = $table }
        $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($n, $d) if ($this.Table.ContainsKey($n)) { $this.Table[$n] } else { $d } }
        return $key
    }
    Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
}
