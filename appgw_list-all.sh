#!/bin/bash
az network application-gateway list --query "[].id" -o json > appgw_inventory.json

