---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Get-NMMAllNetworks

## SYNOPSIS
Gets a list of every network available for a customer account

## SYNTAX

```
Get-NMMAllNetworks [[-nmmId] <Int32>] [<CommonParameters>]
```

## DESCRIPTION
Gets a list of every network available for a customer account, including name, region, resource group, subnets (along with name, and CIDR).

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-NMMAllNetworks -nmmID 57

id                : /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNet
                    works/{vnetName}
name              : {vnetName}
regionName        : {region}
resourceGroupName : {rg}
subnets           : {@{name={snetName}; addressPrefix={CIDR}}, @{name={snetName}; addressPrefix={CIDR}}}
```

## PARAMETERS

### -nmmId
NMM Customer ID

```yaml
Type: Int32
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
