function Get-ADCert()
{

    if(!$(Get-Module -Name "PSPKI" -ErrorAction SilentlyContinue))
    {
        Write-Warning "PSPKI Module is required to run this function, but was not found." 
        Write-Warning "To install, run 'Install-Module PSPKI' with administrative privileges"       
        return
    }

    $CertTemplates = Get-CertificateTemplate 
    $Table = @()
    foreach($Template in $CertTemplates)
    {
        $CertName = $Template.Name
        $Enrollment = $Template.AutoenrollmentAllowed
        $SubjectName = $Template.settings.SubjectName
        $Usage = $Template.Settings.EnhancedKeyUsage.friendlyname -join ", "
        $Type = $Template.Settings.SubjectType
        $ACLs = Get-CertificateTemplateAcl $Template

        foreach($ACL in $ACLs)
        {
            $Owner = $ACL.owner
    
            foreach($Access in $ACL.access)
            {
                $Pso = [pscustomobject]@{}
                $Identity = $Access.IdentityReference
                $TemplateRights = $Access.CertificateTemplateRights
    
                $Pso | Add-Member -MemberType NoteProperty -Name "CertName" -value $CertName 
                $Pso | Add-Member -MemberType NoteProperty -Name "CertType" -value $Type
                $Pso | Add-Member -MemberType NoteProperty -Name "Identity" -value $Identity 
                $Pso | Add-Member -MemberType NoteProperty -Name "TemplateRights" -value $TemplateRights                 
                $Pso | Add-Member -MemberType NoteProperty -Name "Owner" -value $Owner 
                $Pso | Add-Member -MemberType NoteProperty -Name "Enrollment" -value $Enrollment 
                $Pso | Add-Member -MemberType NoteProperty -Name "SubjectName" -value $SubjectName    
                $Pso | Add-Member -MemberType NoteProperty -Name "Usage" -value $Usage 
                $Table += $Pso
            }
        }
    }
    return $Table
}

#$Table = Get-CertificateSecurity
#$Table | Out-GridView
#$certsec                                                                                                                                                                                                                                                                                                    
#$certsec | ft                                                                                                                                                                                                                                                                                               
#$certsec | sort identity | ft                                                                                                                                                                                                                                                                               
#$certsec | sort name | ft                                                                                                                                                                                                                                                                                   
#$certsec | sort name | ? { $_.name -match 'InternalServer'} |  ft                                                                                                                                                                                                                                           
#$certsec | sort name | ? { $_.name -imatch 'InternalServer'} |  ft                                                                                                                                                                                                                                          
#$certsec | sort name | ? { $_.name -imatch 'internal'} |  ft                                                                                                                                                                                                                                                
#$certsec | sort name | ? { $_.name -imatch 'internal'} |  ft                                                                                                                                                                                                                                                
#$certsec | sort name | ? { $_.certname -imatch 'internal'} |  ft                                                                                                                                                                                                                                            
#$certsec | sort name | ? { $_.certname -imatch 'internal'} |  ft                                                                                                                                                                                                                                            
#$certsec | sort name | ? { $_.usage -imatch 'authentication'} |  ft                                                                                                                                                                                                                                         
#$certsec | sort name | ? { $_.identity -imatch 'user'} |  ft                                                                                                                                                                                                                                                
#$certsec | sort name | ? { $_.identity -imatch 'user'} |  ?{ $_.usage -match "auth" } |ft 
