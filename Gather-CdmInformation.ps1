<# Gather-CdmInformation.ps1
##
## Version: 1.1.00 BN 002 (04/19/2021) Added recursive zone processing
##          1.0.00 BN 001 (10/29/2020) Initial Release
##
#>

<#
.SYNOPSIS
This script collects Centrify Role Assignment information from a Centrify Zone.

.DESCRIPTION
This script collections all 3 different types of Role Assignments within a Centrify Zone:

Zone-Wide Assignments
Computer Role Assignments
Computer-specific Assignments

In addition, it bundles information about the relevant Role Definition used with that
Role Assignment, including the Command Rights used as part of that Role Definition.

The end result is a variable (or .xml file) that can be used to search for Role
Assignment information more effectively.

This script requires PowerShell version 5.1 and the Centrify DirectControl PowerShell 
module.

.PARAMETER Zone
This is the simple name (e.g. "Global") of the zone to collection Role Assignment information.
A Distinguished Name can be used instead for the Zone object in the event there are multiple
zones with the same name.

.PARAMETER Version
Show version of this script.

.PARAMETER Help
Show usage for this script.

.INPUTS
None. You can't redirect or pipe input to this script.

.OUTPUTS
This script output two files in the same directory that the script is executed.

.EXAMPLE
C:\PS> .\Gather-CdmInformation.ps1 -Zone Global
This script collects Role Assignments, Role Defintions, and Command Right information from
the Global zone.

.EXAMPLE
C:\PS> .\Gather-CdmInformation.ps1 - Zone "CN=Unix,CN=Zones,OU=Centrify,DC=domain,DC=com"
This script collects Role Assignments, Role Defintions, and Command Right information from
the Unix zone. The Distinguished Name is used here to be explicit which zone is to be used.
This is for situations when where there are multiple zones that have the same name.

.EXAMPLE
C:\PS> .\Gather-CdmInformation.ps1 -Version
Displays the current version of the script.

.EXAMPLE
C:\PS> .\Gather-CdmInformation.ps1 -Help
Displays what you are seeing now.
#>

#######################################
#region ### PARAMETERS ################
#######################################
[CmdletBinding(DefaultParameterSetName="Default")]
Param
(
    #region ### General Parameters ###

    ### Validators ###
    #[ValidateScript({If (-Not (Test-Path -Path ($_))) {Throw "The specified file does not exist. Please enter the name of the file."} Else { $true } })]
    #[ValidateNotNullOrEmpty()]

    [Parameter(Mandatory = $true, HelpMessage ="The target Centrify Zone to begin analyzing.")]
    [ValidateNotNullOrEmpty()]
    [System.String]$Zone,

    [Parameter(Mandatory = $true, HelpMessage = "Display the version of the script.", ParameterSetName="Version")]
    [Alias("v")]
    [Switch]$Version,

    [Parameter(Mandatory = $true, HelpMessage = "Display extra help.", ParameterSetName="Help")]
    [Alias("?")]
    [Alias("h")]
    [Switch]$Help
    #endregion

)# Param

#######################################
#endregion ############################
#######################################

#######################################
#region ### CONFIG VARIABLES ##########
#######################################



#######################################
#endregion ############################
#######################################

#######################################
#region ### VERSION NUMBER and HELP ###
#######################################

[System.String]$VersionNumber = (Get-Content ($MyInvocation.MyCommand).Name)[2]

# print the version number if -Version was used and exit
if ($Version.IsPresent)
{
	Write-Host ("{0} ({1})`n" -f ($MyInvocation.MyCommand).Name,$VersionNumber)
	Exit 0 # EXITCODE 0 : Successful execution
}

#
if ($Help.IsPresent)
{
	Invoke-Expression -Command ("Get-Help .\{0} -Full" -f ($MyInvocation.MyCommand).Name)
	Exit 0 # EXITCODE 0 : Successful execution
}
#######################################
#endregion ############################
#######################################

#######################################
#region ### FUNCTIONS #################
#######################################

###########
#region ### Check-Module # Checks for and imports the necessary PowerShell modules.
function Check-Module
{
    Param
    (
        [Parameter(Position = 0, HelpMessage="The module to check.")]
        [System.String]$Module
    )# Param

    Write-Verbose ("-------------------")
    Write-Verbose ("Check-Module called")
    Write-Verbose ("-------------------")

    # if the module hasn't already been imported
    if (-Not (Get-Module -ListAvailable).Name.Contains($Module))
    {
        # if the module is available
        if ((Get-Module -ListAvailable).Name.Contains($Module))
        {
            # try importing it
            Try
            {
                Import-Module -Name $Module
            }
            Catch
            {
                Write-Error ($_.Exception)
                Exit 2 # EXITCODE 2 : Unknown error while importing required module.
            }
        }# f ((Get-Module -ListAvailable).Name.Contains($Module))
        else
        {
            Write-Error ("Required Module [{0}] was not found." -f $Module)
            Exit 1 # EXITCODE 1 : Required module not found.
        }
    }# if (-Not (Get-Module).Contains($Module))


}# function Check-Module
#endregion
###########

###########
#region ### TEMPLATE # TEMPLATE
#function TEMPLATE
#{
#}# function TEMPLATE
#endregion
###########

#######################################
#endregion ############################
#######################################


#######################################
#region ### PREPIFY ###################
#######################################

# Add the required modules
Check-Module -Module Centrify.DirectControl.PowerShell
Check-Module -Module ActiveDirectory

# including the library.ps1 file
. .\library.ps1

# checking to ensure the zone exists

# if the Zone is using the Distinguished Name format
if ($Zone -like "CN=*")
{
    # if the Zone is not found using the Distinguished Name format
    if (-Not ($TargetZone = Get-CdmZone -Dn $Zone))
    {
        Write-Host ("The Target Zone was not found using the Distinguished Name.")
        Write-Host ("Zone : [{0}]" -f $Zone)
        Exit 3 # EXITCODE 3 : Target Zone not found.
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

            Exit 4 # EXITCODE 4 : Multiple Target Zones found.
        }# if ($TargetZone.Count -gt 1)
    }# if ($TargetZone = Get-CdmZone -Name $Zone)
    else
    {
        #Zone not found
        Write-Host ("The Target Zone was not found using the common name.")
        Write-Host ("Zone : [{0}]" -f $Zone)
        Exit 3 # EXITCODE 3 : Target Zone not found.
    }
}# else # the Zone is using the common name

# now getting all the zones that need to be processed
$Zones = Get-CdmZone | Where-Object {$_.Name -eq $TargetZone.Name -or $_.Parent -like ("*{0}" -f $TargetZone.DistinguishedName)} | Sort-Object CanonicalName

#######################################
#endregion ############################
#######################################

#######################################
#region ### MAIN ######################
#######################################

# ArrayLists for storing all our information
[System.Collections.ArrayList] $AllCentrifyRoles       = @()   
[System.Collections.ArrayList] $AllCentrifyAssignments = @()

foreach ($TargetZone in $Zones)
{
    ### ZONE ROLES ###

    Write-Host ("Gathering Roles in Centrify Zone [{0}]" -f $TargetZone.Name) -ForegroundColor Yellow

    # getting all the roles in the target zone
    $Roles = Get-CdmRole -Zone $TargetZone

    # making a copy of those CdmRole objects to add new properties
    $CentrifyRoles = $Roles.PSObject.Copy()

    # adding additional property fields, no data yet though
    $CentrifyRoles | Add-Member -MemberType NoteProperty -Name CdmCommandRight     -Value CdmCommandRight
    $CentrifyRoles | Add-Member -MemberType NoteProperty -Name CdmPamRight         -Value CdmPamRight
    $CentrifyRoles | Add-Member -MemberType NoteProperty -Name CdmApplicationRight -Value CdmApplicationRight

    # for each role we gathered
    foreach ($role in $CentrifyRoles)
    {
        # add the command rights and pam rights to our custom role object
	    $role.CdmCommandRight     = Get-CdmCommandRight     -Role $role
	    $role.CdmPamRight         = Get-CdmPamRight         -Role $role
        $role.CdmApplicationRight = Get-CdmApplicationRight -Role $role

        $AllCentrifyRoles.Add($role) | Out-Null
    }# foreach ($role in $CentrifyRoles)

    ### ZONE ROLES ASSIGNMENTS ###
    Write-Host ("Working on Zone-Wide Role Assignments for Zone [{0}]" -f $TargetZone.Name) -ForegroundColor Yellow

    # Getting all zone-wide role assignments
    $ZoneAssignments = Get-CdmRoleAssignment -Zone $TargetZone
    
    if ($ZoneAssignments.Count -gt 0)
    {
        # making a copy of those CdmRoleAssignment objects to add new properties
        $TmpAssignments = $ZoneAssignments.PSObject.Copy()

        # adding additional property fields, no data yet though except for the Zone name
        $TmpAssignments | Add-Member -MemberType NoteProperty -Name CdmRoleAssignmentType -Value CdmRoleAssignmentType
        $TmpAssignments | Add-Member -MemberType NoteProperty -Name CdmRoleAssignment     -Value CdmRoleAssignment
        $TmpAssignments | Add-Member -MemberType NoteProperty -Name TrusteeName           -Value TrusteeName
        $TmpAssignments | Add-Member -MemberType NoteProperty -Name AssignmentTarget      -Value $TargetZone.Name

        # for each assignment we found
        foreach ($assignment in $TmpAssignments)
        {
	        # setting the role name and the distinguished name of the zone
	        $rolename = $assignment.Role.Name
	        $rolezone = $assignment.Role.Zone.DistinguishedName
	
            # our CdmRoleAssignmentType is Zone
	        $assignment.CdmRoleAssignmentType = "Zone"

            # setting the CdmRole object into our custom object
	        $assignment.CdmRoleAssignment     = $CentrifyRoles | Where-Object {$_.Name -eq $rolename -and $_.Zone.DistinguishedName -eq $rolezone}

            # setting our TrusteeName based on which trustee is used
            if ($assignment.AdTrustee -eq $null)
            {
                $assignment.TrusteeName = $assignment.LocalTrustee
            }
            else
            {
                $assignment.TrusteeName = $assignment.AdTrustee
            }

            # adding it to our assignments 
	        $AllCentrifyAssignments.Add($assignment) | Out-Null
        }# foreach ($assignment in $TmpAssignments)
    }# if ($ZoneAssignments.Count -gt 0)
    else
    {
         Write-Host ("No zone wide assignments found in Zone [{0}]" -f $TargetZone.Name) -ForegroundColor Yellow
    }

    ### COMPUTER ROLES ###
    Write-Host ("Working on Computer-Role Role Assignments in Zone [{0}]" -f $TargetZone.Name) -ForegroundColor Yellow

    # Getting all computer roles
    $ComputerRoles = Get-CdmComputerRole -Zone $TargetZone

    if ($ComputerRoles.Count -gt 0)
    {
    # for each computer role we found
        foreach ($computerrole in $ComputerRoles)
        {
	        # for each role assignment we found in each computer role
	        foreach ($crroleassignment in (Get-CdmRoleAssignment -ComputerRole $computerrole))
	        {
                # setting additional properties
		        $rolename = $crroleassignment.Role.Name
		        $rolezone = $crroleassignment.Role.Zone.DistinguishedName	
		        $cdmrole  = $CentrifyRoles | Where-Object {$_.Name -eq $rolename -and $_.Zone.DistinguishedName -eq $rolezone}
                $computerrolename = $tmproleassignment.ComputerRole.Name

	
                # making a copy of each CdmRoleAssignment object to add new properties
		        $tmproleassignment = $crroleassignment.PSObject.Copy()
		        $tmproleassignment | Add-Member -MemberType NoteProperty -Name CdmRoleAssignmentType -Value "ComputerRole"
		        $tmproleassignment | Add-Member -MemberType NoteProperty -Name CdmRoleAssignment     -Value $cdmrole
                $tmproleassignment | Add-Member -MemberType NoteProperty -Name TrusteeName           -Value TrusteeName
                $tmproleassignment | Add-Member -MemberType NoteProperty -Name AssignmentTarget      -Value $computerrolename

                # setting the TrusteeName based on which one was used
                if ($tmproleassignment.AdTrustee -eq $null)
                {
                    $tmproleassignment.TrusteeName = $tmproleassignment.LocalTrustee
                }
                else
                {
                    $tmproleassignment.TrusteeName = $tmproleassignment.AdTrustee
                }

                # adding it to our assignments 
		        $AllCentrifyAssignments.Add($tmproleassignment) | Out-Null
	        }# foreach ($crroleassignment in (Get-CdmRoleAssignment -ComputerRole $computerrole))
        }# foreach ($computerrole in $ComputerRoles)
    }# if ($ComputerRoles.Count -gt 0)
    else
    {
        Write-Host ("No computer roles found in Zone [{0}]" -f $TargetZone.Name) -ForegroundColor Yellow
    }

        
    ### COMPUTERS ###
    Write-Host ("Working on Computer-Specific Role Assignments in Zone [{0}]" -f $TargetZone.Name) -ForegroundColor Yellow

    # Getting all computer joined to our Target Zone
    $Computers = Get-CdmManagedComputer -Zone $TargetZone

    if ($Computers.Count -gt 0)
    {
        # for each computer we found 
        foreach ($computer in $Computers)
        {
            # and for each role assignment found on that computer
	        foreach ($cmproleassignment in (Get-CdmRoleAssignment -Computer $computer))
	        {
                # setting additional properties
		        $rolename     = $cmproleassignment.Role.Name
		        $rolezone     = $cmproleassignment.Role.Zone.DistinguishedName
		        $cdmrole      = $CentrifyRoles | Where-Object {$_.Name -eq $rolename -and $_.Zone.DistinguishedName -eq $rolezone}
                $computername = $tmpcmproleassignment.Computer.Name

                # making a copy of each CdmRoleAssignment object to add new properties
		        $tmpcmproleassignment = $cmproleassignment.PSObject.Copy()
		        $tmpcmproleassignment | Add-Member -MemberType NoteProperty -Name CdmRoleAssignmentType -Value "Computer"
		        $tmpcmproleassignment | Add-Member -MemberType NoteProperty -Name CdmRoleAssignment     -Value $cdmrole
                $tmpcmproleassignment | Add-Member -MemberType NoteProperty -Name TrusteeName           -Value TrusteeName
                $tmpcmproleassignment | Add-Member -MemberType NoteProperty -Name AssignmentTarget      -Value $computername

                # setting the TrusteeName based on which one was used
                if ($tmpcmproleassignment.AdTrustee -eq $null)
                {
                    $tmpcmproleassignment.TrusteeName = $tmpcmproleassignment.LocalTrustee
                }
                else
                {
                    $tmpcmproleassignment.TrusteeName = $tmpcmproleassignment.AdTrustee
                }

                # adding it to our assignments
		        $AllCentrifyAssignments.Add($tmpcmproleassignment) | Out-Null
	        }# foreach ($cmproleassignment in (Get-CdmRoleAssignment -Computer $computer))
        }# foreach ($computer in $Computers)
    }# if ($Computers.Count -gt 0)
    else
    {
        Write-Host ("No computers found in Zone [{0}]" -f $TargetZone.Name) -ForegroundColor Yellow
    }
    
}# foreach ($TargetZone in $Zones)

# export the custom role objects as an .xml file that can be used later
$AllCentrifyRoles | Export-Clixml .\AllCentrifyRoles.xml

# setting this as a global variable
$global:AllCentrifyRoles = $AllCentrifyRoles

# export the custom role assignment objects as an .xml file that can be used later
$AllCentrifyAssignments | Export-Clixml .\AllCentrifyAssignments.xml

# setting this as a global variable
$global:AllCentrifyAssignments = $AllCentrifyAssignments

Exit 0 # EXITCODE 0 : Successful execution

#######################################
#endregion ############################
#######################################