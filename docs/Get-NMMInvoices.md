---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Get-NMMInvoices

## SYNOPSIS
Get your Nerdio invoice for a specific time period.

## SYNTAX

```
Get-NMMInvoices [-startTime] <DateTime> [-endTime] <DateTime> [<CommonParameters>]
```

## DESCRIPTION
Get your Nerdio invoice for a specific time period.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-NMMInvoices -startTime 01/01/2023 -endTime 01/31/2023

id                 : xxxxx
displayId          : NMMPxxxxx
billingPeriod      : 1/1/2023 12:00:00 AM
startBillingPeriod : 1/1/2023 12:00:00 AM
endBillingPeriod   : 2/1/2023 12:00:00 AM
discounts          : XXXX, XXXX, XXXX
status             : Paid
acceptedDateTime   : 1/31/2023 5:08:35 PM
paidDateTime       : 1/31/2023 5:32:36 PM
desktopUsersCount  : 40743.124525673299
cpcUsersCount      : 0
intuneUsersCount   : 15201
mauCount           : 0
acceptedCharges    : 0
currency           : USD
invoiceItems       : <individual invoice data goes here>
```

This will pull an invoice for your desired period, you need to enter the first day of the month and the last day of the month you're looking for. 

## PARAMETERS

### -endTime
Required to be entered as MM/dd/YYYY format. Ensure it is the last day of the month.

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -startTime
Required to be entered as MM/dd/YYYY format. Ensure it is the first of the month.

```yaml
Type: DateTime
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
