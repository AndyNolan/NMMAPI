---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Get-NMMCustomers

## SYNOPSIS
Gets all NMM customers in your instance.

## SYNTAX

```
Get-NMMCustomers [[-search] <String>] [<CommonParameters>]
```

## DESCRIPTION
Gets all NMM customers in your instance.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-NMMCustomers
id name
-- ----
 1 Andy Nolan
 2 Andy Nolan Dev Tenant
 3 Andy Nolan Gamma Tenant
 4 Yet Another Andy Test ENV
```

### Example 2

```powershell
PS C:\> Get-NMMCustomers -search tenant
id name
-- ----
 2 Andy Nolan Dev Tenant
 3 Andy Nolan Gamma Tenant
```

## PARAMETERS

### -search
Simple text search if you'd like to filter your results. Can be helpful if you have a lot of accounts.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
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
