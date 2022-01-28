#!/bin/python
import json
import boto3
import csv
from typing import Any, Protocol
import os
import pandas as pd
import glob
import os as os
import glob as gl
import sys
from xlsxwriter.workbook import Workbook
import pathlib


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
csv_content_sg  = "Region, Group_Name, Group_ID, From_Port, To_port, CIDR, Tag_Name\n"

csv_file_nacl = open ("/tmp/nacl.csv", "w")
csv_content_nacl  = "Region, NACL_ID, VPC_ID, Rule_NO, CIDR, Egress, Rule_Action\n"

csv_file_fw = open ("/tmp/fw.csv", "w")
csv_content_fw  = "Region, RuleGroupName, Protocl, Source_IP, SourcePort, Destination_IP, DestinationPort, Direction\n"

ec2_client = boto3.client('ec2')
response = ec2_client.describe_regions()
regions_data = response ["Regions"]

for regions in regions_data:
    Name = regions["RegionName"]

    #### Secuirty Groups ####
    session = boto3.Session(region_name=Name)
    client = session.client('ec2')
    ec2 = boto3.resource('ec2')
    response1=client.describe_security_groups()
    sg_data = response1 ["SecurityGroups"]

    for sg in sg_data:
         # get Name tag if exists
        if 'Tags' in sg:
            for tag in sg['Tags']:
                name_tag_not_found = False
                if tag['Key'] == "Name":
                    sg_name_tag = tag['Value']
                else:
                    name_tag_not_found = True
            if name_tag_not_found:
                sg_name_tag = ''
            
        else:
            sg_name_tag = ''

        if len(sg['IpPermissions']) == 0:
            fromPort = ''
            toPort = ''
            cidr = ''
            csv_content_sg += "{},{},{},{},{},{},{}\n".format(Name, sg["GroupName"], sg["GroupId"], fromPort, toPort, cidr, sg_name_tag)
        
        else:
            for portDetails in sg['IpPermissions']:
                if "FromPort" in portDetails:
                    fromPort = portDetails.get( 'FromPort', '')
                    toPort = portDetails.get ('ToPort', '')

                    for ip in portDetails['IpRanges']:
                        cidr = ip['CidrIp']
                        csv_content_sg += "{},{},{},{},{},{},{}\n".format(Name, sg["GroupName"], sg["GroupId"], fromPort, toPort, cidr, sg_name_tag)
                else: 
                    fromPort = ''
                    toPort = ''

                    if len(portDetails['IpRanges']) == 0:
                        cidr = ''
                        csv_content_sg += "{},{},{},{},{},{},{}\n".format(Name, sg["GroupName"], sg["GroupId"], fromPort, toPort, cidr, sg_name_tag)
                    else:
                        for ip in portDetails['IpRanges']:
                            if len(portDetails['IpRanges']) == 0:
                                cidr = ''
                            else:
                                cidr = ip.get('IpRanges', '' )
                                csv_content_sg += "{},{},{},{},{},{},{}\n".format(Name, sg["GroupName"], sg["GroupId"], fromPort, toPort, cidr, sg_name_tag)


    #### NACLs ####
    session = boto3.Session(region_name=Name)
    client = session.client('ec2')
    ec2 = boto3.resource('ec2')
    response2=client.describe_network_acls()
    nacl_data = response2 ["NetworkAcls"]

    for nacl in nacl_data:
        vpc_id = nacl.get("VpcId")
        naclID = nacl.get("NetworkAclId")          
        for entry in nacl["Entries"]:
            rule_no = entry.get("RuleNumber")
            cidr_block = entry.get("CidrBlock")
            egress = entry.get("Egress")
            rule_action = entry.get("RuleAction")
            if not entry[ 'Egress' ]:
                print(entry)

            csv_content_nacl += "{},{},{},{},{},{},{}\n".format(Name, naclID, vpc_id, rule_no, cidr_block, egress, rule_action)


    #### Firewall Rule Groups ####

    session = boto3.Session(region_name=Name)
    client = session.client('network-firewall')
    ec2 = boto3.resource('ec2')
    response3 = client.list_rule_groups()
    fw_rule_list = response3 ['RuleGroups']
    for fw_rule in fw_rule_list:
        rule_group = fw_rule.get('Arn')

        session = boto3.Session(region_name=Name)
        client = session.client('network-firewall')
        ec2 = boto3.resource('ec2')
        response4 = client.describe_rule_group(RuleGroupArn = str(rule_group))
        fw_rule_desc = response4 ['RuleGroup']

        for stateRules in fw_rule_desc[ 'RulesSource' ][ 'StatefulRules' ]:
            SourcePort = stateRules['Header']['SourcePort'].replace("[","").replace("]","")
            direction = stateRules['Header']['Direction']
            destPort = stateRules['Header']['DestinationPort'].replace("[","").replace("]","")
            protocol = stateRules['Header']['Protocol']
            source_ip = stateRules['Header']['Source'].replace("[","").replace("]","").replace(",",";")
            destiP = stateRules['Header']['Destination'].replace("[","").replace("]","")
            csv_content_fw += "{},{},{},{},{},{},{},{}\n".format(Name, fw_rule['Name'], protocol, source_ip, SourcePort, destiP, destPort, direction)   
        

csv_file_sg.write (csv_content_sg)
csv_file_nacl.write (csv_content_nacl)
csv_file_fw.write (csv_content_fw)

#### Code ####

csv_file_sg.close()
csv_file_nacl.close()
csv_file_fw.close()

tmpPath = '/tmp/'
os.chdir(r"/tmp/")
writer = pd.ExcelWriter('securityreport.xlsx', engine='xlsxwriter')
for csvFile in os.listdir( tmpPath ):
    if csvFile.endswith( 'csv' ):
        fileName = pathlib.Path( csvFile )
        inCsv = pd.read_csv( os.path.join( tmpPath, csvFile ), error_bad_lines=False, engine ='python' )
        inCsv.to_excel( writer, sheet_name = fileName.stem, index = False )
    
writer.save()

#### 2nd Code ####

#path = '/tmp'
#all_files = glob.glob(os.path.join(path, "*.csv"))

#writer = pd.ExcelWriter('out.xlsx', engine='xlsxwriter')

#for f in all_files:
#    df = pd.read_csv(f)
#    df.to_excel(writer, sheet_name=os.path.splitext(os.path.basename(f))[0], index=False)

#writer.save()

#### 3rd Code ####

"""with open('output.csv', "rt", encoding = 'UTF-8') as fin:
    with open('outputconvert.csv', "wt", encoding = 'UTF-8') as fout:
        for line in fin:
            fout.write(line.replace(';',','))"""

#workbook = Workbook('out.xlsx')
#for csvfile in glob.glob(os.path.join('.', '*.csv')):
#    worksheet = workbook.add_worksheet('testws')
#    with open(csvfile, 'rt', encoding='utf8') as f:
#        reader = csv.reader(f)
#        for r, row in enumerate(reader):
#            for c, col in enumerate(row):
#                worksheet.write(r, c, col)
#    workbook.close()
    
#### 4th Code ####

#Excel_File = pd.ExcelFile("new_excel_filename.xlsx")
#Sheet_Name = Excel_File.sheet_names
#length_of_Sheet = len(Excel_File.sheet_names)
#print("List of sheets in you xlsx file :\n",Sheet_Name)

#for i in range(0,length_of_Sheet):
#    df = pd.read_excel("new_excel_filename.xlsx", sheet_name = i)
#    df = df.iloc[:,0:3]
#    df.to_csv(Sheet_Name[i]+".csv", index = False)
#    print("Created :",Sheet_Name[i],".csv")
    
#filenames = [i for i in gl.glob('*.{}'.format('csv'))]
#combined_csv = pd.concat([pd.read_csv(f) for f in filenames ])
#combined_csv.to_csv( "combined_csv_filename.csv", index=False, encoding='utf-8-sig')

#writer = pd.ExcelWriter('default.xlsx') # Arbitrary output name
#for csvfilename in sys.argv[1:]:
#    df = pd.read_csv(csvfilename)
#    df.to_excel(writer,sheet_name=os.path.splitext(csvfilename)[0])
#writer.save()

###########
def lambda_handler(event,context):
    
    srcFile = '/tmp/securityreport.xlsx'
    bucketName = 'aws-securityreport'


#def uploadToS3( bucketName: str, srcFile: str ):
    taskStatus = False
    try:
        s3_client = boto3.client('s3')
        uploadResp = s3_client.upload_file( srcFile, bucketName, 'securityreport.xlsx' )
        print( "Upload Resp ", uploadResp )
    except Exception as errMsg:
        print( errMsg )
    else:
        taskStatus = True
        
    return taskStatus

#if __name__ == '__main__':
#    lambda_handler(None, None)    
