@{
    RootModule = 'OpsToolkit.Hardening.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'd4a7e9b1-6c2f-4f38-9a51-3e8b7c0d2f65'
    Author = 'Jon Bowker'
    Description = 'Shared host-context detection (join state, VDI session host, MDM management) and the org settings file reader used by the windows-hardening scripts.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @(
        'Get-OpsHostContext'
        'Get-OpsOrgSettings'
        'Get-OpsPolicyOverrideNote'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
