---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Get-NMMCustomerRecoveryPoints

## SYNOPSIS
Gets all recovery points for a specific item.

## SYNTAX

```
Get-NMMCustomerRecoveryPoints [-nmmId] <Int32> [[-protectedItemId] <String>] [<CommonParameters>]
```

## DESCRIPTION
Gets all recovery points for a specific item.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-NMMCustomerRecoveryPoints -nmmId 57 -protectedItemId "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;{rg};{vm}/protectedItems/VM;iaasvmcontainerv2;{rg};{vm}"
```

You will likely want to pipe data collected from recovery vaults or protected items. 

## PARAMETERS

### -nmmId
NMM Customer ID

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -protectedItemId
{{ Fill protectedItemId Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases: id

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.Int32

### System.String

## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS
