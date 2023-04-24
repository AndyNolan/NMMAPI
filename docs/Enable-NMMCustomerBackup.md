---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Enable-NMMCustomerBackup

## SYNOPSIS
Enables backups for a specific resource.

## SYNTAX

```
Enable-NMMCustomerBackup [-sourceResourceId] <String> [[-backupPolicy] <String>] [[-nmmId] <Int32>]
 [<CommonParameters>]
```

## DESCRIPTION
Enables backups for a specific resource. Must specify the sourceResourceId, backupPolicy and nmmId.

## EXAMPLES

### Example 1
```powershell
PS C:\> Enable-NMMCustomerBackup -nmmId 57 -sourceResourceId "/subscriptions/e0b52e85-7caf-4260-a772-c0d82e56d407/ResourceGroups/resource-group-1/providers/Microsoft.Compute/virtualmachines/vm-name-1" -backupPolicy "/subscriptions/e0b52e85-7caf-4260-a772-c0d82e56d407/ResourceGroups/resource-group-1/providers/Microsoft.RecoveryServices/vaults/TestVault/backupPolicies/TestPolicy"
```

## PARAMETERS

### -backupPolicy
Full resource ID of the backup policy.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -nmmId
NMM Customer ID

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sourceResourceId
Full resource ID of the object to be backed up.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None

## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS
