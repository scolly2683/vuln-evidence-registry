<#
.SYNOPSIS
    Collect evidence that decides whether a scanner detection is real.

.DESCRIPTION
    Analyst-runnable evidence gathering for detection storms. Every function
    here is READ-ONLY and non-destructive: it opens files and reads process
    lists. Nothing is modified, nothing is deleted, no exploit is sent.

    It answers the questions the triage playbook asks, in order:

      Test-VulnerableJar    Is the vulnerable CLASS actually inside the jar?
                            (Separates "log4j 2.14.1 on disk" from "actually
                            vulnerable". The official Log4Shell fix REMOVED
                            JndiLookup.class without changing the version, so
                            version-string detections stay red after patching.)

      Get-ArtifactContext   Is this a dead copy? (backup / crash dump / temp /
                            old release folder) - those need cleanup, not a
                            patch, and must not be silently suppressed.

      Test-ProcessUsingPath Is anything actually running from this location?

      Export-EvidenceCsv    Write results in a shape you can paste into the
                            triage tool or attach to a suppression.

.NOTES
    Requires PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform).
    No modules to install. Run as a user that can read the paths in scope.

    This script does NOT test exploitability over the network. Active testing
    (canary/OAST callbacks) needs written authorisation and change control -
    see the triage playbook. Passive evidence first; it usually settles it.

.EXAMPLE
    . .\9-Get-CveEvidence.ps1
    $r = Test-VulnerableJar -Path 'D:\apps' -Recurse
    $r | Where-Object Verdict -eq 'VULNERABLE' | Format-Table

.EXAMPLE
    # Everything at once, ready for the triage tool
    Get-CveEvidenceReport -Path 'D:\apps' | Export-EvidenceCsv -Out '.\evidence.csv'
#>

Set-StrictMode -Version Latest

# Known "the vulnerable code lives in this class" checks. Extend as needed:
# the pattern generalises to any CVE where the fix removes or renames a class.
$script:ClassChecks = @{
    'CVE-2021-44228' = @{
        Name        = 'Log4Shell'
        FilePattern = 'log4j-core*.jar'
        ClassPath   = 'org/apache/logging/log4j/core/lookup/JndiLookup.class'
        NotAffected = @('log4j-api*.jar', 'log4j-1.*.jar', 'log4j-over-slf4j*.jar')
        Note        = 'log4j-api and log4j 1.x are NOT vulnerable to CVE-2021-44228.'
    }
}

function Test-VulnerableJar {
    <#
    .SYNOPSIS
        Look inside jars for the vulnerable class. Read-only.
    .OUTPUTS
        Objects with Path, Cve, Verdict, Reason, SizeKB, LastWrite.
        Verdict is VULNERABLE | PATCHED | NOT_AFFECTED_ARTIFACT | UNREADABLE.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]] $Path,
        [string] $Cve = 'CVE-2021-44228',
        [switch] $Recurse
    )

    $check = $script:ClassChecks[$Cve]
    if (-not $check) { throw "No class check defined for $Cve. Add one to `$script:ClassChecks." }

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $files = foreach ($p in $Path) {
        if (Test-Path -LiteralPath $p -PathType Leaf) { Get-Item -LiteralPath $p }
        else { Get-ChildItem -LiteralPath $p -Filter '*.jar' -File -Recurse:$Recurse -ErrorAction SilentlyContinue }
    }

    foreach ($f in $files) {
        # Artefacts that carry the name but not the vulnerability.
        $notAffected = $false
        foreach ($pat in $check.NotAffected) { if ($f.Name -like $pat) { $notAffected = $true } }
        if ($notAffected) {
            [pscustomobject]@{ Path = $f.FullName; Cve = $Cve; Verdict = 'NOT_AFFECTED_ARTIFACT'
                Reason = $check.Note; SizeKB = [math]::Round($f.Length / 1KB); LastWrite = $f.LastWriteTime }
            continue
        }
        if ($f.Name -notlike $check.FilePattern) { continue }

        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($f.FullName)
            try {
                $hit = $zip.Entries | Where-Object { $_.FullName -eq $check.ClassPath }
                if ($hit) {
                    [pscustomobject]@{ Path = $f.FullName; Cve = $Cve; Verdict = 'VULNERABLE'
                        Reason = "$($check.ClassPath) present"; SizeKB = [math]::Round($f.Length / 1KB); LastWrite = $f.LastWriteTime }
                } else {
                    [pscustomobject]@{ Path = $f.FullName; Cve = $Cve; Verdict = 'PATCHED'
                        Reason = 'vulnerable class removed - version string may still look old'
                        SizeKB = [math]::Round($f.Length / 1KB); LastWrite = $f.LastWriteTime }
                }
            } finally { $zip.Dispose() }
        } catch {
            [pscustomobject]@{ Path = $f.FullName; Cve = $Cve; Verdict = 'UNREADABLE'
                Reason = $_.Exception.Message; SizeKB = [math]::Round($f.Length / 1KB); LastWrite = $f.LastWriteTime }
        }
    }
}

function Get-ArtifactContext {
    <#
    .SYNOPSIS
        Classify WHERE the file lives: live deployment, or a dead copy.
    .DESCRIPTION
        Dead copies (backups, crash dumps, temp extracts, old releases) are not
        exploitable, but they are also not suppression material - they should be
        deleted. This makes that distinction explicit and reviewable.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipelineByPropertyName)][string] $Path)

    process {
        $deadMarkers = @('\\backup', '\\bak\\', '\.bak$', '\\old\\', '\\archive', '\\crash',
                         '\\temp\\', '\\tmp\\', '\\var\\crash', '\\_old', '\\previous', '\\rollback')
        $isDead = $false; $marker = ''
        foreach ($m in $deadMarkers) {
            if ($Path -match $m) { $isDead = $true; $marker = $m; break }
        }
        [pscustomobject]@{
            Path       = $Path
            Context    = if ($isDead) { 'DEAD_COPY' } else { 'LIVE_PATH' }
            Marker     = $marker
            Action     = if ($isDead) { 'Raise cleanup finding - delete, do not suppress' }
                         else { 'Treat as live until proven otherwise' }
        }
    }
}

function Test-ProcessUsingPath {
    <#
    .SYNOPSIS
        Is any running process executing from, or loading files under, this path?
    .DESCRIPTION
        Read-only. Helps separate "present on disk" from "actually running".
        Absence of evidence is not proof - a process may load the jar later.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    $norm = $Path.TrimEnd('\', '/')
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $p = $null
        try { $p = $_.Path } catch { }
        ($p -and $p -like "$norm*") -or
        ($_.Modules 2>$null | Where-Object { $_.FileName -like "$norm*" })
    }
    if ($procs) {
        foreach ($p in $procs) {
            [pscustomobject]@{ Path = $norm; InUse = $true; ProcessName = $p.ProcessName; Pid = $p.Id }
        }
    } else {
        [pscustomobject]@{ Path = $norm; InUse = $false; ProcessName = $null; Pid = $null }
    }
}

function Get-CveEvidenceReport {
    <#
    .SYNOPSIS
        Run the whole waterfall over a path and return one row per artefact.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]] $Path,
        [string] $Cve = 'CVE-2021-44228'
    )
    Test-VulnerableJar -Path $Path -Cve $Cve -Recurse | ForEach-Object {
        $ctx = Get-ArtifactContext -Path $_.Path
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Cve          = $_.Cve
            Path         = $_.Path
            Verdict      = $_.Verdict
            Context      = $ctx.Context
            Reason       = $_.Reason
            Action       = if ($ctx.Context -eq 'DEAD_COPY') { $ctx.Action }
                           elseif ($_.Verdict -eq 'VULNERABLE') { 'Real - route to fix channel' }
                           elseif ($_.Verdict -eq 'PATCHED') { 'Close as remediated - detection is stale' }
                           elseif ($_.Verdict -eq 'NOT_AFFECTED_ARTIFACT') { 'Suppress with this evidence' }
                           else { 'Manual check' }
            LastWrite    = $_.LastWrite
            CheckedOn    = (Get-Date).ToString('yyyy-MM-dd')
        }
    }
}

function Export-EvidenceCsv {
    <#
    .SYNOPSIS
        Write evidence rows to CSV for the triage tool or a suppression record.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $InputObject,
        [Parameter(Mandatory)][string] $Out
    )
    begin { $rows = @() }
    process { $rows += $InputObject }
    end {
        $rows | Export-Csv -LiteralPath $Out -NoTypeInformation -Encoding UTF8
        Write-Host "Wrote $($rows.Count) rows to $Out" -ForegroundColor Green
        $summary = $rows | Group-Object Verdict | Sort-Object Count -Descending
        foreach ($g in $summary) { Write-Host ("  {0,-24} {1}" -f $g.Name, $g.Count) }
    }
}

Write-Host @"
CVE evidence helpers loaded (read-only, non-destructive).

  Test-VulnerableJar    -Path <dir> [-Recurse]   is the vulnerable class present?
  Get-ArtifactContext   -Path <file>             live path or dead copy?
  Test-ProcessUsingPath -Path <dir>              is anything running from it?
  Get-CveEvidenceReport -Path <dir>              all of the above, one row each
  Export-EvidenceCsv    -Out evidence.csv        pipe a report into this

Start with:  Get-CveEvidenceReport -Path 'D:\apps' | Export-EvidenceCsv -Out .\evidence.csv
"@ -ForegroundColor Cyan
