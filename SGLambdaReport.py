#!/bin/python
import json
import boto3
import csv
from typing import Any, Protocol

def convert_to_json(o: Any) -> Any:
    t = type(o)

    if t is dict:
        return {k: convert_to_json(v) for k, v in o.items()}

    elif t is list or t is set:
        return [convert_to_json(item) for item in o]

    elif t is int or t is float or t is str or t is bool or o is None:
        return o

    else:
        return str(o)
        
csv_file_sg = open ("/tmp/sg.csv", "w")
csv_content_sg  = "Region, Group_Name, Group_ID, From_Port, To_port, CIDR\n"

ec2_client = boto3.client('ec2')
response = ec2_client.describe_regions()
regions_data = response ["Regions"]
print (response)
for regions in regions_data:
    Name = regions["RegionName"]

    #### Secuirty Groups ####
    session = boto3.Session(region_name=Name)
    client = session.client('ec2')
    ec2 = boto3.resource('ec2')
    response1=client.describe_security_groups()
    sg_data = response1 ["SecurityGroups"]
    print(response1)