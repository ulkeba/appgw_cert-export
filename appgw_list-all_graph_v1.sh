#!/bin/bash
az graph query --graph-query 'resources | where type == "microsoft.network/applicationgateways" | where not (properties["sku"]["name"] endswith "v2")| project  id' --query "data[].id" -o json > appgw_inventory.json

