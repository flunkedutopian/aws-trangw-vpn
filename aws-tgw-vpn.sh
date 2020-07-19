#aws ec2 create-key-pair --key-name eastuskp --query 'KeyMaterial' --output text > eastuskp.pem
#eastuskpid=$(aws ec2 describe-key-pairs --filters "Name=key-name, Values=eastkusp" --query "KeyPairs[0].KeyPairId" --output text)
#aws ec2 create-tags --resources $eastuskpid --tags Key=Name,Value=eastuskp
#chmod 400 eastuskp.pem
#ssh-add eastuskp.pem

#https://docs.aws.amazon.com/vpn/latest/s2svpn/SetUpVPNConnections.html
#reference: https://awstrainingcenter-test.s3-us-east-2.amazonaws.com/10+-+Setup+Site+to+Site+VPN+Connection+in+AWS.pdf

#VPC and Sub CIDR Variables for AWS and OP
awsvpccidr="10.1.0.0/16"
awssubcidr="10.1.0.0/24"
opvpccidr="10.2.0.0/16"
opsubcidr="10.2.0.0/24"


#Create VPC, Subnet, Routetable, associate Route table with subnet - awsvpc -- represents AWS
awsvpc=$(aws ec2 create-vpc --cidr-block $awsvpccidr | jq '.Vpc.VpcId' | tr -d '"')
awssub=$(aws ec2 create-subnet --vpc-id $awsvpc --cidr-block $awssubcidr --availability-zone us-east-2a | jq '.Subnet.SubnetId' | tr -d '"')
awssubrtb=$(aws ec2 create-route-table --vpc-id $awsvpc | jq '.RouteTable.RouteTableId' | tr -d '"')
aws ec2 associate-route-table --route-table-id $awssubrtb --subnet-id $awssub
#tag them
aws ec2 create-tags --resources $awssubrtb --tags Key=Name,Value=awssubrtb
aws ec2 create-tags --resources $awssub --tags Key=Name,Value=awssub
aws ec2 create-tags --resources $awsvpc --tags Key=Name,Value=awsvpc


#Create VPC, Subnet, Routetable, associate Route table with subnet - op
onpremvpc=$(aws ec2 create-vpc --cidr-block $opvpccidr | jq '.Vpc.VpcId' | tr -d '"')
opsub=$(aws ec2 create-subnet --vpc-id $onpremvpc --cidr-block $opsubcidr --availability-zone us-east-2a | jq '.Subnet.SubnetId' | tr -d '"')
opsubrtb=$(aws ec2 create-route-table --vpc-id $onpremvpc | jq '.RouteTable.RouteTableId' | tr -d '"')
aws ec2 associate-route-table --route-table-id $opsubrtb --subnet-id $opsub
#tag them 
aws ec2 create-tags --resources $opsub --tags Key=Name,Value=opsub
aws ec2 create-tags --resources $onpremvpc --tags Key=Name,Value=onpremvpc
aws ec2 create-tags --resources $opsubrtb --tags Key=Name,Value=opsubrtb


#create & attach internet gateway - onprem
tigwid=$(aws ec2 create-internet-gateway | jq '.InternetGateway.InternetGatewayId' | tr -d '"')
aws ec2 attach-internet-gateway --vpc-id $onpremvpc --internet-gateway-id $tigwid
#insert route for internet - onprem subnet route table
aws ec2 create-route --route-table-id $opsubrtb --destination-cidr-block 0.0.0.0/0 --gateway-id $tigwid
#Figure your public IP Addr
mypubip=$(dig +short myip.opendns.com @resolver1.opendns.com)
#or dig TXT +short o-o.myaddr.l.google.com @ns1.google.com
#Create secgroup for ssh and lauch instance - onprem
opsgid=$(aws ec2 create-security-group --group-name opvpnserversg --description "Security group for op vpnserver" --vpc-id $onpremvpc | jq '.GroupId' | tr -d '"')
aws ec2 create-tags --resources $opsgid --tags Key=Name,Value=opvpnsg
#enable ssh from my pub ip
aws ec2 authorize-security-group-ingress --group-id $opsgid --protocol tcp --port 22 --cidr $mypubip/32


#Create an ec2 instance in op subnet to host openvpn
opserverid=$(aws ec2 run-instances --image-id ami-016b213e65284e9c9 --count 1 --instance-type t2.micro --key-name eastuskp --security-group-ids $opsgid --subnet-id $opsub --associate-public-ip-address --query 'Instances[0].InstanceId' --output text)
aws ec2 modify-instance-attribute --instance-id $opserverid --no-source-dest-check
aws ec2 create-tags --resources $opserverid --tags Key=Name,Value=opserverid
#check of previous instance with same name tag is existent or not, based on that change the reservation index
vpnservIP=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=opserverid" --query 'Reservations[0].Instances[0].NetworkInterfaces[0].PrivateIpAddresses[0].Association.PublicIp' --output text)

#on aws vpc:
cgwid=$(aws ec2 create-customer-gateway --bgp-asn 65000 --type ipsec.1 --public-ip $vpnservIP --query 'CustomerGateway.CustomerGatewayId' --output text)
aws ec2 create-tags --resources $cgwid --tags Key=Name,Value=cgw
#create tgw
trangwid=$(aws ec2 create-transit-gateway --description hubtrangw \
    --options=AmazonSideAsn=64516,AutoAcceptSharedAttachments=enable,DefaultRouteTableAssociation=enable,DefaultRouteTablePropagation=enable,VpnEcmpSupport=enable,DnsSupport=enable \
	--query "TransitGateway.TransitGatewayId" --output text)
# or use this
# trangwid=$(aws ec2 create-transit-gateway --description hubtrangw --options=AmazonSideAsn=64516,AutoAcceptSharedAttachments=enable,DefaultRouteTableAssociation=enable,DefaultRouteTablePropagation=enable,VpnEcmpSupport=enable,DnsSupport=enable | jq '.TransitGateway.TransitGatewayId' | tr -d '"')
#tag it
aws ec2 create-tags --resources $trangwid --tags Key=Name,Value=trangw
#check its state, wait till its available
aws ec2 describe-transit-gateways --filter "Name=tag:Name,Values=trangw" --query "TransitGateways[0].State" --output text
#create vpn connection using transit gateway
aws ec2 create-vpn-connection --type ipsec.1 --customer-gateway-id $cgwid --transit-gateway-id $trangwid --options "{\"StaticRoutesOnly\":true}"
#Find the transit gateway attachment ID - check index id for TransitGatewayAttachments appropriately before issuing the command
vpntrgwattid=$(aws ec2 describe-transit-gateway-attachments --filter "Name=transit-gateway-id,Values=$trangwid" --query "TransitGatewayAttachments[2].TransitGatewayAttachmentId" --output text)
#attach aws-vpc to transit gateway
vpctrgwattid=$(aws ec2 create-transit-gateway-vpc-attachment --transit-gateway-id $trangwid --vpc-id $awsvpc --subnet-id $awssub --query "TransitGatewayVpcAttachment.TransitGatewayAttachmentId" --output text)
#tag it
aws ec2 create-tags --resources $vpctrgwattid --tags Key=Name,Value=vpctrgwattid
aws ec2 create-tags --resources $vpntrgwattid --tags Key=Name,Value=vpntrgwattid
#find the routetable associated with the transit gateway
trangwrtbid=$(aws ec2 describe-transit-gateways --filter "Name=transit-gateway-id,Values=$trangwid" --query "TransitGateways[0].Options.AssociationDefaultRouteTableId" --output text)
#Create route to op cidrsubnet in transit gateway route table through the attachment
aws ec2 create-transit-gateway-route --destination-cidr-block $opsubcidr --transit-gateway-route-table-id $trangwrtbid --transit-gateway-attachment-id $vpntrgwattid
#Create route to op sub cidr in aws sub route table:
aws ec2 create-route --route-table-id $awssubrtb --destination-cidr-block $opsubcidr --gateway-id $trangwid

#after roughly 5-10 min, the status of the transit gateway attachment changes to available, go to s2s vpn connections & download the config
#login to the openswan server
----------------------------------------------------------------------------------------------------------------------------------------------------
#10.1.0.0/16 -- AWS ENV
#10.2.0.0/16 -- On Prem

sudo yum install openswan -y #Install openswan
sudo cat /etc/ipsec.conf #check last line status should be uncommented (include /etc/ipsec.d/*.conf)
sudo nano /etc/ipsec.d/connection.conf
conn VpnConn1
 authby=secret
 auto=start
 left=%defaultroute
 leftid=3.135.249.93 #leftid=cgwip (#3 TunnelInterfaceConfig: Outside IP Addresses: Customer Gateway)
 right=3.17.198.242 #right=vpgwip (#3 TunnelInterfaceConfig: Outside IP Addresses: Virtual Private Gateway)
 type=tunnel
 ikelifetime=8h
 keylife=1h
 phase2alg=aes128-sha1;modp1024
 ike=aes128-sha1;modp1024
 keyingtries=%forever
 keyexchange=ike
 leftsubnet=10.2.0.0/24
 rightsubnet=10.1.0.0/24
 dpddelay=10
 dpdtimeout=30
 dpdaction=restart_by_peer

sudo nano /etc/ipsec.d/connections.secrets
3.135.249.93 3.17.198.242: PSK "wkJIEWVpj2TzPr7jtYCtwZsAuTGL4Wyd"
#cgw-ip vgw-ip: PSK "PRE_SHARED_KEY"

sudo nano /etc/sysctl.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.default.accept_source_route = 0

sudo systemctl restart network #service network restart then #sudo chkconfig ipsec on
sudo systemctl start ipsec #sudo service ipsec start
sudo systemctl status ipsec
----------------------------------------------------------------------------------------------------------------------------------------------------
#post above changes, successful outcome can be measured by: 
aws ec2 describe-vpn-connections --query "VpnConnections[0].VgwTelemetry[0]"
#{
#    "AcceptedRouteCount": 0,
#    "LastStatusChange": "2020-07-19T06:05:15+00:00",
#    "OutsideIpAddress": "3.17.198.242",
#    "Status": "UP",
#    "StatusMessage": ""
#}

#Create secgroup for ssh and launch instance - aws
awsec2sgid=$(aws ec2 create-security-group --group-name awsec2accesssg --description "Security group aws ec2 access" --vpc-id $awsvpc | jq '.GroupId' | tr -d '"')
aws ec2 authorize-security-group-ingress --group-id $awsec2sgid --protocol tcp --port 22 --cidr $opsubcidr
awsec2inst=$(aws ec2 run-instances --image-id ami-016b213e65284e9c9 --count 1 --instance-type t2.micro --key-name eastuskp --security-group-ids $awsec2sgid --subnet-id $awssub  --query 'Instances[0].InstanceId' --output text)
aws ec2 create-tags --resources $awsec2inst --tags Key=Name,Value=awsec2inst
