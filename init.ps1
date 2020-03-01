function New-SecureAksEnvironmentVariables {
    [CmdletBinding()]
    param()

    $Prefix = "crgar-aks-secure"
    $ResourceGroup = "${Prefix}-rg"
    $Location = "eastus"
    $Name = "${Prefix}20190212"
    $AcrName = "${Name}acr"
    $VnetName = "${Prefix}vnet"
    $AKSSubnetName = "${Prefix}akssubnet"
    $SvcSubnetName = "${Prefix}svcsubnet"
    $AciSubnetName = "${Prefix}acisubnet"
    # DO NOT CHANGE FWSUBNET_NAME - This is currently a requirement for Azure Firewall.
    $FwSubnetName = "AzureFirewallSubnet"
    $AppGwSubnetName = "${Prefix}appgwsubnet"
    $WorkspaceName = "${Prefix}k8slogs"
    $IdentityName = "${Prefix}identity"
    $FwName = "${Prefix}fw"
    $FwPublicIpName = "${Prefix}fwpublicip"
    $FwIpConfigName = "${Prefix}fwconfig"
    $FwRouteTableName = "${Prefix}fwrt"
    $FwRouteName = "${Prefix}fwrn"
    $AgNAme = "${Prefix}ag"
    $AgPublicIpName = "${Prefix}agpublicip"

    $SubscriptionNAme = "crgar Internal Subscription"
}

function New-SecureAksResourceGroup {
    [CmdletBinding()]
    param ()

    # Get ARM Access Token and Subscription ID - This will be used for AuthN later.
    $AccessToken = $(az account get-access-token -o tsv --query 'accessToken')
    # NOTE: Update Subscription Name
    $SubscriptionId = $(az account show -s $SubscriptionNAme -o tsv --query 'id')
    # Create Resource Group
    az group create --name $ResourceGroup --location $Location
}

function New-SecureAksVNets
{
    [CmdletBinding()]
    param ()

    az network vnet create `
        --resource-group $ResourceGroup `
        --name $VnetName `
        --address-prefixes 10.42.0.0/16 `
        --subnet-name $AksSubnetName `
        --subnet-prefix 10.42.1.0/24

    az network vnet subnet create `
        --resource-group $ResourceGroup `
        --vnet-name $VnetName `
        --name $SvcSubnetName `
        --address-prefix 10.42.2.0/24

    az network vnet subnet create `
        --resource-group $ResourceGroup `
        --vnet-name $VnetName `
        --name $AciSubnetName `
        --address-prefix 10.42.3.0/24

    az network vnet subnet create `
        --resource-group $ResourceGroup `
        --vnet-name $VnetName `
        --name $FwSubnetName `
        --address-prefix 10.42.4.0/24

    az network vnet subnet create `
        --resource-group $ResourceGroup `
        --vnet-name $VnetName `
        --name $AppGwSubnetName `
        --address-prefix 10.42.5.0/24
}