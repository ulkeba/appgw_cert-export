#!/bin/bash
az graph query --graph-query 'resources | where type == "microsoft.network/applicationgateways"' --query "data[].id" -o json > appgw_inventory.json

