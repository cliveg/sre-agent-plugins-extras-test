@{
    RootModule        = 'Az.ResourceGraph.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '6b1c3f5e-0d7a-4c55-9f3e-7f2a3b9d1e01'
    Author            = 'sre-agent-plugins-extras (wara-assessment)'
    Description       = 'Restricted-egress stand-in for Az.ResourceGraph: implements only Search-AzGraph over the Azure Resource Graph REST API. Used when the PowerShell Gallery is not reachable. Not a Microsoft module.'
    PowerShellVersion = '7.0'
    RequiredModules   = @(@{ ModuleName = 'Az.Accounts'; ModuleVersion = '3.0.0' })
    FunctionsToExport = @('Search-AzGraph')
    CmdletsToExport   = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('wara-assessment', 'shim') } }
}
