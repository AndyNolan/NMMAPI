---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Unregister-NMMRecoveryVault

## SYNOPSIS
Unlinks a recovery vault from NMM

## SYNTAX

```
Unregister-NMMRecoveryVault [-nmmId] <Int32> [-vaultID] <String> [<CommonParameters>]
```

## DESCRIPTION
Unlinks a recovery vault from NMM

## EXAMPLES

### Example 1
```powershell
PS C:\> Unregister-NMMRecoveryVault -nmmId 57 -vaultId "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.RecoveryServices/vaults/{vaultName}"
```

Unlinks a recovery vault from NMM

## PARAMETERS

### -nmmId
NMM Customer ID

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: id

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -vaultID
{{ Fill vaultID Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
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
