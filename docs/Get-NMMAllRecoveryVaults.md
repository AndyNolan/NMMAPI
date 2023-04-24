---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Get-NMMAllRecoveryVaults

## SYNOPSIS
Gets a list of all Recovery Vaults for an account, not just linked ones.

## SYNTAX

```
Get-NMMAllRecoveryVaults [[-nmmId] <Int32>] [<CommonParameters>]
```

## DESCRIPTION
Gets a list of all Recovery Vaults for an account, not just linked ones.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-NMMAllRecoveryVaults -nmmId 57
name              : BackupVault
resourceGroupName : ResourceGroup
region            : AzureRegion
policies          : {@{id=/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.RecoveryServ
                    ices/vaults/{backupVault}/backupPolicies/DefaultPolicy; name=DefaultPolicy; schedule=Daily: 2:30 
                    AM; type=VirtualMachine}, @{id=/subscriptions/{sub}/resourceGroups/{rg}/provide
                    rs/Microsoft.RecoveryServices/vaults/{backupVault}/backupPolicies/{backupPolicy}; 
                    name={backupPolicy}; schedule=Daily: 2:00 AM; type=VirtualMachine}}
id                : /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.RecoveryServices/v
                    aults/{backupVault}
portalLink        : https://portal.azure.com/linkGoesHere
```

## PARAMETERS

### -nmmId
NMM Customer ID

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: id

Required: False
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Int32

## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS
