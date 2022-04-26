enum CategoryType
{
    SIMPLE
    COMPLEX
}

enum CommandRisk
{
    LOW
    MEDIUM
    HIGH
}

class CentrifyZone
{
    [System.Collections.ArrayList]$Roles
    [System.Collections.ArrayList]$Assignments
    [System.Collections.ArrayList]$Systems

    CentrifyZone ()
    {

    }
}

class CentrifyImplementation
{
    [System.Collections.ArrayList]$AllCentrifyRoles
    [System.Collections.ArrayList]$AllCentrifyAssignments
    
    CentrifyImplementation($acr, $aca)
    {
        $this.AllCentrifyRoles       = $acr
        $this.AllCentrifyAssignments = $aca
    }

    removeDefaultRoles()
    {
        $this.AllCentrifyRoles = $this.AllCentrifyRoles | Where-Object { `
            $_.Name -ne "listed" -and `
            $_.Name -ne "local listed" -and `
            $_.Name -ne "require MFA for login" -and `
            $_.Name -ne "always permit login" -and `
            $_.Name -ne "Rescue - always permit login" -and `
            $_.Name -ne "scp" -and `
            $_.Name -ne "sftp" -and `
            $_.Name -ne "UNIX Login" -and `
            $_.Name -ne "Windows Login" -and `
            $_.Name -ne "winscp" `
        }
    }
}# class CentrifyImplementation

class CentrifyCategory
{
    [System.String] $CategoryName
    [Regex]         $Regex
    [System.String] $RegexString
    [CategoryType]  $Category

    CentrifyCategory([System.String]$cn, [System.String]$r, [System.String]$c)
    {
        $this.CategoryName = $cn
        $this.Regex        = $r
        $this.RegexString  = $r
        $this.Category     = $c
    }
}


#region ### Determine-CommandRisk # Determines the risk level of commands
function global:Determine-CommandRisk ($commandrightpattern)
{
    $CommandRisk = $null

    Switch -Regex ($commandrightpattern)
    {
        "1" {$CommandRisk = [CommandRisk]::LOW; break}
        default { $CommandRisk = [CommandRisk]::MEDIUM; break }

    }# Switch -Regex ($commandrightpattern)
    
    # returning our results joined together with an OR "|" in regex
    return $CommandRisk
}# function global:ConvertCommandsToRegex ($commandrightpatterns)
#endregion

#region ### ConvertCommandTo-Regex # Converts string commands into a single regex OR statement
function global:ConvertCommandTo-Regex ($commandrightpatterns)
{
    $Commands = New-Object System.Collections.ArrayList

    # for each command pattern sent to us
    foreach ($commandrightpattern in $commandrightpatterns)
    {
        $clip = $commandrightpattern

        # adding escape characters
        $clip = $clip.Replace(".","\.")
        $clip = $clip.Replace("*","\*")
        $clip = $clip.Replace("?","\?")
        $clip = $clip.Replace("/","\/")
        $clip = $clip.Replace("-","\-")

        # adding parentheses
        $clip = "({0})" -f $clip

        $Commands.Add($clip) | Out-Null
        
    }# foreach ($commandrightpattern in $commandrightpatterns)

    # returning our results joined together with an OR "|" in regex
    return ($Commands -join "|")
}# function global:ConvertCommandsToRegex ($commandrightpatterns)
#endregion

#region ### Remove-DefaultRoles # Removes all premade roles from the Role Stack
function global:Remove-DefaultRoles ($AllCentrifyRoles)
{
    $AllCentrifyRoles = $AllCentrifyRoles | Where-Object { `
        $_.Name -ne "listed" -and `
        $_.Name -ne "local listed" -and `
        $_.Name -ne "require MFA for login" -and `
        $_.Name -ne "always permit login" -and `
        $_.Name -ne "Rescue - always permit login" -and `
        $_.Name -ne "scp" -and `
        $_.Name -ne "sftp" -and `
        $_.Name -ne "UNIX Login" -and `
        $_.Name -ne "Windows Login" -and `
        $_.Name -ne "winscp" `
        }

    return $AllCentrifyRoles
}# function global:Remove-DefaultRoles ($AllCentrifyRoles)
#endregion

#region ### Find-CentrifyZones # Recurisvely finds all Centrify zones from a source zone
function global:Find-CentrifyZones([System.String]$Zone)
{
    # if the Zone is using the Distinguished Name format
    if ($Zone -like "CN=*")
    {
        # if the Zone is not found using the Distinguished Name format
        if (-Not ($TargetZone = Get-CdmZone -Dn $Zone))
            {
                Write-Host ("The Target Zone was not found using the Distinguished Name.")
                Write-Host ("Zone : [{0}]" -f $Zone)
                Exit 1 # EXITCODE 1 : Target Zone not found.
            }
    }# if ($Zone -like "CN=*")
    else # the Zone is using the common name
    {
        if ($TargetZone = Get-CdmZone -Name $Zone)
        {
            # if more than one Zone was found
            if ($TargetZone.Count -gt 1)
            {
                Write-Warning ("Multiple Zones exist with the Target Name [{0}]." -f $Zone)
                Write-Host ("Use the Distinguished Name format instead.")

                foreach ($z in $TargetZone)
                {
                    Write-Host ("Zone : [{0}]" -f $z.Name)
                    Write-Host ("DN   : [{0}]" -f $z.DistinguishedName)
                }

                Exit 3 # EXITCODE 3 : Multiple Target Zones found.
            }# if ($TargetZone.Count -gt 1)
        }# if ($TargetZone = Get-CdmZone -Name $Zone)
        else
        {
            #Zone not found
            Write-Host ("The Target Zone was not found using the common name.")
            Write-Host ("Zone : [{0}]" -f $Zone)
            Exit 2 # EXITCODE 2 : Target Zone not found.
        }
    }# else # the Zone is using the common name

    # now getting all the zones that need to be processed
    $Zones = Get-CdmZone | Where-Object {$_.Name -eq $TargetZone.Name -or $_.Parent -like ("*{0}" -f $TargetZone.DistinguishedName)} | Sort-Object CanonicalName

    return $Zones
}
#endregion

function global:Find-EmptyZones($AllRoles, $AllAssignments, $AllZones, $AllSystems)
{
    $EmptyAssignments = New-Object System.Collections.ArrayList
    $EmptySystems     = New-Object System.Collections.ArrayList

    foreach ($zone in $AllZones)
    {
        $zoneassignments = $AllAssignments | Where-Object {$_.Zone.DistinguishedName -eq $zone.distinguishedName}

        if ($zoneassignments.Count -eq 0)
        {
            $EmptyAssignments.Add($zone) | Out-Null
        }

        $zonesystems = $AllSystems | Where-Object {$_.Zone.DistinguishedName -eq $zone.distinguishedName}

        if ($zonesystems.Count -eq 0)
        {
            $EmptySystems.Add($zone) | Out-Null
        }
    }

    return $EmptyAssignments, $EmptySystems
}

function global:Find-EmptyZonesInParallel($AllAssignments, $AllZones, $AllSystems)
{
    $EmptyAssignments = New-Object System.Collections.ArrayList
    $EmptySystems     = New-Object System.Collections.ArrayList

    $AllZones | Foreach-Object -Parallel {
        $zone = $_


        $zoneassignments = $null
        $zonesystems     = $null

        #$zoneassignments = $AllAssignments | Where-Object {$_.Zone.CanonicalName -match $zone.CanonicalName}
        #$zoneassignments = $using:AllAssignments | Where-Object {$_.Zone.CanonicalName -eq $zone.CanonicalName}
        $zoneassignments = $using:AllAssignments | Where-Object {$_.Zone.DistinguishedName -like ("*{0}" -f $Zone.DistinguishedName)}

        #Write-Host ("Zone Assignment [{0}]" -f $zoneassignments.Count)

        if ($zoneassignments.Count -eq 0)
        {
            ($using:EmptyAssignments).Add($zone) | Out-Null
        }

        #$zonesystems = $AllSystems | Where-Object {$_.Zone.CanonicalName -match $zone.CanonicalName}
        #$zonesystems = $using:AllSystems | Where-Object {$_.Zone.CanonicalName -eq $zone.CanonicalName} #this works
        $zonesystems = $using:AllSystems | Where-Object {$_.Zone.DistinguishedName -like ("*{0}" -f $Zone.DistinguishedName)}

        if ($zonesystems.Count -eq 0)
        {
            ($using:EmptySystems).Add($zone) | Out-Null
        }
    }

    return $EmptyAssignments, $EmptySystems
}

$AllZones       = Import-Clixml .\AllCentrifyZones.xml
$AllAssignments = Import-Clixml .\AllCentrifyAssignments.xml
$AllSystems     = Import-Clixml .\AllCentrifySystems.xml

$ea, $es = Find-EmptyZonesInParallel -AllAssignments $AllAssignments -AllZones $AllZones -AllSystems $AllSystems

$global:ea = $ea
$global:es = $es