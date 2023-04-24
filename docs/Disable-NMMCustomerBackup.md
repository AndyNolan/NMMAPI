---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Disable-NMMCustomerBackup

## SYNOPSIS

Removes customer backup, based on parameters.

## SYNTAX

```
Disable-NMMCustomerBackup [-sourceResourceId] <String> [[-protectedItemId] <String>] [[-nmmId] <Int32>]
 [[-removeAllBackups] <Boolean>] [<CommonParameters>]
```

## DESCRIPTION

Disables backup for a resource, with the option to remove all historical backups.

## EXAMPLES

### Example 1

```powershell
PS C:\> Disable-NMMCustomerBackup -nmmID 57 -sourceResourceId "/subscriptions/e0b52e85-7caf-4260-a772-c0d82e56d407/ResourceGroups/resource-group-1/providers/Microsoft.Compute/virtualmachines/vm-name-1" -protectedItemId "/subscriptions/e0b52e85-7caf-4260-a772-c0d82e56d407/resourceGroups/resource-group-1/providers/Microsoft.RecoveryServices/vaults/TestVault/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;resource-group-1;vm-name-1/protectedItems/VM;iaasvmcontainerv2;resource-group-1;vm-name-1"
```

This will disable backing up the virtual machine "vm-name-1" identified via `sourceResourceId`. If you were to specify `-removeAllBackups $true` then all previous backups would be destroyed.

## PARAMETERS

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

### -protectedItemId

{{ Fill protectedItemId Description }}

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

### -removeAllBackups

{{ Fill removeAllBackups Description }}

```yaml
Type: Boolean
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sourceResourceId

{{ Fill sourceResourceId Description }}

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
