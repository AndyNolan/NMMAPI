---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Get-NMMCustomerSecureVariable

## SYNOPSIS
Gets a list of secure vars defined for a customer account.

## SYNTAX

```
Get-NMMCustomerSecureVariable [[-nmmId] <Int32>] [<CommonParameters>]
```

## DESCRIPTION
Gets a list of secure vars defined for a customer account.

## EXAMPLES

### Example 1

```powershell
PS C:\> Get-NMMCustomerSecureVariable -nmmId 57

name      scriptedActions
----      ---------------
var1      {}
var2      {}
var3      {}
var4      {}
```

List of vars, and if applicable, any scriptedActions that they are specifically bound to.

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
