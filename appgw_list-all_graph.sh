#!/bin/bash
az graph query --graph-query 'resources | where type == "microsoft.network/applicationgateways" | project id' --query "data[].id" -o json > appgw_inventory.json

