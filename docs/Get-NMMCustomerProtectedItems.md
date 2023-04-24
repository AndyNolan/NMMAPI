---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Get-NMMCustomerProtectedItems

## SYNOPSIS
Get a list of all items backed up.

## SYNTAX

```
Get-NMMCustomerProtectedItems [-nmmId] <Int32> [<CommonParameters>]
```

## DESCRIPTION
Get a list of all items backed up.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-NMMCustomerProtectedItems -nmmId 57
```

API response data:
    "id": "string",
    "friendlyName": "string",
    "sourceResourceId": "string",
    "protectedItemType": "string",
    "protectionState": "string",
    "lastBackupStatus": "string",
    "lastRestorePoint": "2023-04-24T02:57:25.364Z",
    "softDeleted": true,
    "recoveryVault": "string",
    "policyId": "string",
    "vaultIsManaged": true,
    "isBackupInProgress": true,
    "resourceGroupName": "string",
    "rgPortalLink": "string"

Also added a customer nmmId addition for easy piping to other NMMAPI commands.

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
