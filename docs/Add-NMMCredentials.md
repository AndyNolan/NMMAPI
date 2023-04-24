---
external help file: NMMAPI-help.xml
Module Name: NMMAPI
online version:
schema: 2.0.0
---

# Add-NMMCredentials

## SYNOPSIS

Collects required information to connect to an NMM install via REST API.

## SYNTAX

```
Add-NMMCredentials [[-nmmBaseUri] <Uri>] [[-nmmoAuthToken] <Uri>] [[-nmmTenantId] <String>]
 [[-nmmClientId] <String>] [[-nmmScope] <String>] [[-nmmSecretx] <SecureString>] [<CommonParameters>]
```

## DESCRIPTION

Collects required information to connect to an NMM install via REST API.

## EXAMPLES

### Example 1

```powershell
PS C:\> Add-NMMCredentials
Please input your NMM URL, e.g. nmm.democompany.com: nmm.democompany.com
Please input your OAuth 2.0 token: OauthToken:)
Please input your tenant ID: 1234  
Please input your client ID: 5678
Please input your scope: 91011/.default 
Please input your secret: secret!
Testing connectivity to the NMM API located at nmm.democompany.com...
```

If parameters are not automatically applied, user will be prompted to enter relevant data.

## PARAMETERS

### -nmmBaseUri
{{ Fill nmmBaseUri Description }}

```yaml
Type: Uri
Parameter Sets: (All)
Aliases:

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -nmmClientId
{{ Fill nmmClientId Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -nmmScope
{{ Fill nmmScope Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -nmmSecretx
{{ Fill nmmSecretx Description }}

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -nmmTenantId
{{ Fill nmmTenantId Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -nmmoAuthToken
{{ Fill nmmoAuthToken Description }}

```yaml
Type: Uri
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String

## OUTPUTS

### System.Object

## NOTES

## RELATED LINKS
