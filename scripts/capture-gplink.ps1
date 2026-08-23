#Requires -Modules ActiveDirectory, GroupPolicy
# O-03 - gPLink ordering oracle capture.
#
# Creates throwaway OUs and GPOs under OU=oracle-gplink in the current
# domain, applies a matrix of gPLink scenarios, and records VERBATIM:
#   - what AD stores: the raw gPLink attribute string and gPOptions
#   - what GPMC reports: the Get-GPInheritance array for the OU
#
# ORACLE RULE: this script must not compute, sort, derive, or interpret
# link order anywhere. The "reported" array is copied as-is from
# Get-GPInheritance, in the order the API returns it. It is the
# specification D-03's parser is tested against. Do not add fields that
# re-derive order (no expectedPrecedence, no re-sorted list).
#
# The gPLinkOptions numbers in the scenario table below are used only to
# BUILD the scenarios (which string to put on the OU). Every recorded
# value comes from AD or GPMC, never from this script's understanding of
# the bits.
#
# Run on a Windows DC (or RSAT box) in the TEST domain:
#   powershell -ExecutionPolicy Bypass -File scripts/capture-gplink.ps1
# Idempotent: removes OU=oracle-gplink and GPOs named oracle-gplink-*
# from previous runs before starting. See scripts/README-oracles.md.

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory, GroupPolicy

$DomainDN = (Get-ADDomain).DistinguishedName
$Root     = "OU=oracle-gplink,$DomainDN"
$OutDir   = Join-Path (Split-Path $PSScriptRoot -Parent) 'testdata/oracle/gplink'

function New-CaseOU([string]$Name) {
    (New-ADOrganizationalUnit -Name $Name -Path $Root -ProtectedFromAccidentalDeletion $false -PassThru).DistinguishedName
}

function Set-RawLinks([string]$OuDN, [string[]]$Spec, [hashtable]$Dns) {
    $s = [string]::Join('', ($Spec | ForEach-Object {
        $p = $_.Split(';')
        "[LDAP://$($Dns[$p[0]]);$($p[1])]"
    }))
    Set-ADObject -Identity $OuDN -Replace @{ gPLink = @($s) }
}

function Record-Case([string]$Name, [string]$Description, [string]$OuDN, [string]$OutDir) {
    $ad = Get-ADObject -Identity $OuDN -Properties gPLink, gPOptions

    # GPMC's own answer, copied as-is, in the order the API returns it.
    # No sorting, no filtering, no derived fields.
    $inh = Get-GPInheritance -Target $OuDN
    $reported = @()
    if ($null -ne $inh -and $null -ne $inh.GpoLinks) {
        $reported = @($inh.GpoLinks | Select-Object DisplayName, GPOId, Order, Enabled, Enforced)
    }

    $rec = [ordered]@{
        case        = $Name
        description = $Description
        ouDN        = $ad.DistinguishedName
        gPOptions   = $ad.gPOptions
        rawGPLink   = $ad.gPLink
        reported    = $reported
    }
    [System.IO.File]::WriteAllText((Join-Path $OutDir "$Name.json"), ($rec | ConvertTo-Json -Depth 5))

    $raw = $ad.gPLink
    if ($raw -is [array]) { $raw = [string]::Join('', $raw) }
    Write-Host ("  {0,-18} reported={1,-3} raw={2}" -f $Name, $reported.Count, $raw)
}

# ---- idempotent cleanup of previous runs ---------------------------------
Write-Host 'Cleaning previous oracle objects (OU=oracle-gplink, GPOs oracle-gplink-*).'
Get-GPO -All | Where-Object { $_.DisplayName -like 'oracle-gplink-*' } | ForEach-Object {
    Remove-GPO -Guid $_.Id -Confirm:$false
}
$rootExists = $false
try {
    $null = Get-ADObject -Identity $Root
    $rootExists = $true
} catch {
}
if ($rootExists) {
    # OUs are ProtectedFromAccidentalDeletion by default; clear it or the
    # recursive Remove below fails.
    Get-ADOrganizationalUnit -SearchBase $Root -Filter * |
        Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false
    Remove-ADObject -Identity $Root -Recursive -Confirm:$false
}
New-ADOrganizationalUnit -Name 'oracle-gplink' -Path $DomainDN -ProtectedFromAccidentalDeletion $false | Out-Null
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Get-GpoGuid([object]$Gpo) {
    foreach ($prop in @('Id', 'GPOId')) {
        $v = $Gpo.$prop
        if (-not $v) { continue }
        $text = "$v".Trim()
        if ($text -eq '') { continue }
        try {
            return "$([guid]::Parse($text))"
        } catch {
            throw "New-GPO '$($Gpo.DisplayName)': .$prop ('$text') is not a valid GUID. Aborting rather than writing a malformed gPLink DN."
        }
    }
    throw "New-GPO '$($Gpo.DisplayName)' returned no GPO GUID (.Id and .GPOId both empty). Aborting rather than writing cn={}."
}

# ---- scenario GPOs ---------------------------------------------------------
$ga = Get-GpoGuid (New-GPO -Name 'oracle-gplink-a')
$gb = Get-GpoGuid (New-GPO -Name 'oracle-gplink-b')
$gc = Get-GpoGuid (New-GPO -Name 'oracle-gplink-c')
$dl  = $DomainDN.ToLower()
$Dns = @{
    'a' = "cn={$ga},cn=policies,cn=system,$dl"
    'b' = "cn={$gb},cn=policies,cn=system,$dl"
    'c' = "cn={$gc},cn=policies,cn=system,$dl"
}

# ---- scenario matrix --------------------------------------------------------
# spec:   space-separated "<gpo>;<gPLinkOptions>" pairs in the intended
#         STRING order (options: 0 plain, 1 disabled, 2 enforced, 3 both).
# create: cmdlet = New-GPLink, appended in spec order
#         move   = created appended in reverse, repositioned via Set-GPLink
#         raw    = full gPLink string written with Set-ADObject
#                  (disabled bit and same-GPO-twice: cmdlets cannot express)
#         none   = no links
# gPOptions: 1 = block inheritance, written with Set-ADObject
$cases = @(
    @('01_one_link_a',   'one link',                                       'a;0',           'cmdlet', $null),
    @('02_one_link_b',   'one link',                                       'b;0',           'cmdlet', $null),
    @('03_one_link_c',   'one link',                                       'c;0',           'cmdlet', $null),
    @('04_one_enforced', 'one enforced link',                              'a;2',           'cmdlet', $null),
    @('05_two_ab',       'two links, a then b',                            'a;0 b;0',       'cmdlet', $null),
    @('06_two_ba',       'two links, b then a',                            'b;0 a;0',       'cmdlet', $null),
    @('07_two_ac',       'two links, a then c',                            'a;0 c;0',       'cmdlet', $null),
    @('08_two_ca',       'two links, c then a',                            'c;0 a;0',       'cmdlet', $null),
    @('09_two_bc',       'two links, b then c',                            'b;0 c;0',       'cmdlet', $null),
    @('10_two_cb',       'two links, c then b',                            'c;0 b;0',       'cmdlet', $null),
    @('11_three_abc',    'three links, a b c',                             'a;0 b;0 c;0',   'cmdlet', $null),
    @('12_three_acb',    'three links, a c b',                             'a;0 c;0 b;0',   'cmdlet', $null),
    @('13_three_bac',    'three links, b a c',                             'b;0 a;0 c;0',   'cmdlet', $null),
    @('14_three_bca',    'three links, b c a',                             'b;0 c;0 a;0',   'cmdlet', $null),
    @('15_three_cab',    'three links, c a b',                             'c;0 a;0 b;0',   'cmdlet', $null),
    @('16_three_cba',    'three links, c b a (created as a b c, then moved)', 'c;0 b;0 a;0', 'move',   $null),
    @('17_enf_first',    'enforced link at position 1 of 3',               'a;2 b;0 c;0',   'cmdlet', $null),
    @('18_enf_mid',      'enforced link at position 2 of 3',               'a;0 b;2 c;0',   'cmdlet', $null),
    @('19_enf_last',     'enforced link at position 3 of 3',               'a;0 b;0 c;2',   'cmdlet', $null),
    @('20_enf_two',      'enforced links at positions 1 and 3',            'a;2 b;0 c;2',   'cmdlet', $null),
    @('21_dis_first',    'disabled link at position 1 of 3',               'a;1 b;0 c;0',   'raw', $null),
    @('22_dis_mid',      'disabled link at position 2 of 3',               'a;0 b;1 c;0',   'raw', $null),
    @('23_dis_last',     'disabled link at position 3 of 3',               'a;0 b;0 c;1',   'raw', $null),
    @('24_dis_only',     'single disabled link',                           'a;1',           'raw', $null),
    @('25_disenf_first', 'disabled+enforced link at position 1 of 3',      'a;3 b;0 c;0',   'raw', $null),
    @('26_disenf_mid',   'disabled+enforced link at position 2 of 3',      'a;0 b;3 c;0',   'raw', $null),
    @('27_disenf_last',  'disabled+enforced link at position 3 of 3',      'a;0 b;0 c;3',   'raw', $null),
    @('28_disenf_only',  'single disabled+enforced link',                  'a;3',           'raw', $null),
    @('29_dup_0_2',      'same GPO linked twice (plain, then enforced)',   'a;0 a;2',       'raw', $null),
    @('30_dup_2_0',      'same GPO linked twice (enforced, then plain)',   'a;2 a;0',       'raw', $null),
    @('31_dup_0_1',      'same GPO linked twice (plain, then disabled)',   'a;0 a;1',       'raw', $null),
    @('32_dup_3',        'same GPO linked three times (plain, enforced, disabled)', 'a;0 a;2 a;1', 'raw', $null),
    @('33_block_1link',  'block inheritance, one plain link',              'a;0',           'cmdlet', 1),
    @('34_block_enf',    'block inheritance, plain + enforced link',       'a;0 b;2',       'cmdlet', 1),
    @('35_block_empty',  'block inheritance, no links',                    '',              'none', 1),
    @('36_block_disenf', 'block inheritance, disabled+enforced link',      'a;3',           'raw', 1)
)

foreach ($c in $cases) {
    $name = $c[0]
    $spec = @($c[2] -split '\s+' | Where-Object { $_ -ne '' })
    Write-Host "case $name : $($c[1])"
    $ouDN = New-CaseOU $name

    switch ($c[3]) {
        'cmdlet' {
            foreach ($s in $spec) {
                $p = $s.Split(';')
                $gpo = "oracle-gplink-$($p[0])"
                if ([int]$p[1] -band 2) {
                    New-GPLink -Name $gpo -Target $ouDN -Enforced Yes | Out-Null
                } else {
                    New-GPLink -Name $gpo -Target $ouDN | Out-Null
                }
            }
        }
        'move' {
            $rev = @($spec)
            [array]::Reverse($rev)
            foreach ($s in $rev) {
                New-GPLink -Name "oracle-gplink-$($s.Split(';')[0])" -Target $ouDN | Out-Null
            }
            $i = 1
            foreach ($s in $spec) {
                Set-GPLink -Name "oracle-gplink-$($s.Split(';')[0])" -Target $ouDN -Order $i | Out-Null
                $i++
            }
        }
        'raw' {
            Set-RawLinks $ouDN $spec $Dns
        }
    }

    if ($null -ne $c[4]) {
        Set-ADObject -Identity $ouDN -Replace @{ gPOptions = @($c[4]) }
    }

    Record-Case $name $c[1] $ouDN $OutDir
}

Write-Host ''
Write-Host "Captured $($cases.Count) cases to $OutDir"
Write-Host 'Human step: validate a sample against GPMC by eye (scripts/README-oracles.md),'
Write-Host 'then commit testdata/oracle/gplink/ with [test-authoring] in the commit message.'
