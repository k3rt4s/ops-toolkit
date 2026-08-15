@{
    RootModule = 'OpsToolkit.Reporting.psm1'
    ModuleVersion = '1.1.0'
    GUID = 'b3f8c1d2-4e5a-4c9b-8d7e-2a6f1b0c9e34'
    Author = 'Jon Bowker'
    Description = 'Shared report-writing helpers used by ops-toolkit scripts.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @(
        'Resolve-OpsOutputDirectory'
        'Resolve-OpsRunDirectory'
        'Export-OpsReport'
        'Export-OpsSummary'
        'Get-OpsPropertyValue'
        'Join-OpsValue'
        'ConvertTo-OpsHexString'
        'Get-OpsAge'
        'Get-OpsSeverityRank'
        'Get-OpsVolatileColumn'
        'Get-OpsRunDirectory'
        'Compare-OpsRecordSet'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
