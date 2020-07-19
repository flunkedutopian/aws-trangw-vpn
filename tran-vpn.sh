#CIDR Variables
mvpccidr="10.0.0.0/16"
msubcidr="10.0.0.0/24"
w1vpccidr="10.1.0.0/16"
w1subcidr="10.1.0.0/24"

#Create VPC, Subnet, Routetable, associate Route table with subnet - masterVpc
mastervpc=$(aws ec2 create-vpc --cidr-block $mvpccidr | jq '.Vpc.VpcId' | tr -d '"')
msub=$(aws ec2 create-subnet --vpc-id $mastervpc --cidr-block $msubcidr --availability-zone us-east-2a | jq '.Subnet.SubnetId' | tr -d '"')
msubrtb=$(aws ec2 create-route-table --vpc-id $mastervpc | jq '.RouteTable.RouteTableId' | tr -d '"')
aws ec2 associate-route-table --route-table-id $msubrtb --subnet-id $msub
#tag them
aws ec2 create-tags --resources $msubrtb --tags Key=Name,Value=msubrtb
aws ec2 create-tags --resources $msub --tags Key=Name,Value=msub
aws ec2 create-tags --resources $mastervpc --tags Key=Name,Value=mastervpc

#Create VPC, Subnet, Routetable, associate Route table with subnet - WorkerVpc1
workervpc1=$(aws ec2 create-vpc --cidr-block $w1vpccidr | jq '.Vpc.VpcId' | tr -d '"')
w1sub=$(aws ec2 create-subnet --vpc-id $workervpc1 --cidr-block $w1subcidr --availability-zone us-east-2a | jq '.Subnet.SubnetId' | tr -d '"')
w1subrtb=$(aws ec2 create-route-table --vpc-id $workervpc1 | jq '.RouteTable.RouteTableId' | tr -d '"')
aws ec2 associate-route-table --route-table-id $w1subrtb --subnet-id $w1sub
#tag them
aws ec2 create-tags --resources $workervpc1 --tags Key=Name,Value=workervpc1
aws ec2 create-tags --resources $w1sub --tags Key=Name,Value=w1sub
aws ec2 create-tags --resources $w1subrtb --tags Key=Name,Value=w1subrtb

#Create Transit Gateway
trangw=$(aws ec2 create-transit-gateway --description trangw \
    --options=AmazonSideAsn=64516,AutoAcceptSharedAttachments=enable,DefaultRouteTableAssociation=enable,DefaultRouteTablePropagation=enable,VpnEcmpSupport=enable,DnsSupport=enable \
	| jq '.TransitGateway.TransitGatewayId' | tr -d '"')
#tag it
aws ec2 create-tags --resources $trangw --tags Key=Name,Value=trangw    

#attach transit gateway to all vpcs and respective subnets (msub, w1sub, w2sub & w3sub)
aws ec2 create-transit-gateway-vpc-attachment --transit-gateway-id $trangw --vpc-id $mastervpc --subnet-id $msub
aws ec2 create-transit-gateway-vpc-attachment --transit-gateway-id $trangw --vpc-id $workervpc1 --subnet-id $w1sub

#Insert route to w1sub, w2sub, w3sub through Transit Gatewy into msubrtb
aws ec2 create-route --route-table-id $msubrtb --destination-cidr-block $w1subcidr --gateway-id $trangw

#Insert route to msub through Transit Gatewy into w1subrtb
aws ec2 create-route --route-table-id $w1subrtb --destination-cidr-block $msubcidr --gateway-id $trangw
=====================================================================
##run a server on mastervpc
#mserverid=$(aws ec2 run-instances --image-id ami-016b213e65284e9c9 --count 1 --instance-type t2.micro --key-name eastuskp --subnet-id $msub --query 'Instances[0].InstanceId' --output text)
#aws ec2 modify-instance-attribute --instance-id $mserverid --no-source-dest-check
#aws ec2 create-tags --resources $mserverid --tags Key=Name,Value=mserver
##run a server on workervpc #run with --associate-public-ip-address  only to test else not needed for this setup #add your ip to security group
#w1serverid=$(aws ec2 run-instances --image-id ami-016b213e65284e9c9 --count 1 --instance-type t2.micro --key-name eastuskp --subnet-id $w1sub --associate-public-ip-address --query 'Instances[0].InstanceId' --output text)
#aws ec2 modify-instance-attribute --instance-id $w1serverid --no-source-dest-check
#aws ec2 create-tags --resources $w1serverid --tags Key=Name,Value=w1server
=====================================================================
##These steps are onetime to check all in place
##CreateIGW
#tigwid=$(aws ec2 create-internet-gateway | jq '.InternetGateway.InternetGatewayId' | tr -d '"')
#aws ec2 attach-internet-gateway --vpc-id $workervpc1 --internet-gateway-id $tigwid
##insert route for internet - onprem subnet route table
#aws ec2 create-route --route-table-id $w1subrtb --destination-cidr-block 0.0.0.0/0 --gateway-id $tigwid
##post setup deleted removed routes and detached IGW and deleted it
=====================================================================
#Create onprem setup
opvpccidr="10.2.0.0/16"
opsubcidr="10.2.0.0/24"

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
sshopsgid=$(aws ec2 create-security-group --group-name opvpnserversg --description "Security group for SSH access to op vpnserver" --vpc-id $onpremvpc | jq '.GroupId' | tr -d '"')
aws ec2 create-tags --resources $sshopsgid --tags Key=Name,Value=sshopsgid
#enable ssh from my pub ip
aws ec2 authorize-security-group-ingress --group-id $sshopsgid --protocol tcp --port 22 --cidr $mypubip/32
#Create an ec2 instance in op subnet to host openvpn
opserverid=$(aws ec2 run-instances --image-id ami-016b213e65284e9c9 --count 1 --instance-type t2.micro --key-name eastuskp --security-group-ids $sshopsgid --subnet-id $opsub --associate-public-ip-address --query 'Instances[0].InstanceId' --output text)
aws ec2 modify-instance-attribute --instance-id $opserverid --no-source-dest-check
aws ec2 create-tags --resources $opserverid --tags Key=Name,Value=opserverid
#check of previous instance with same name tag is existent or not, based on that change the reservation index
vpnservIP=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=opserverid" --query 'Reservations[0].Instances[0].NetworkInterfaces[0].PrivateIpAddresses[0].Association.PublicIp' --output text)
=====================================================================
#Create CustomerGateway & tag it
cgwid=$(aws ec2 create-customer-gateway --bgp-asn 65000 --type ipsec.1 --public-ip $vpnservIP --query 'CustomerGateway.CustomerGatewayId' --output text)
aws ec2 create-tags --resources $cgwid --tags Key=Name,Value=cgw

#find the routetable associated with the transit gateway
trangwrtbid=$(aws ec2 describe-transit-gateways --filter "Name=tag:Name,Values=trangw" --query "TransitGateways[0].Options.AssociationDefaultRouteTableId" --output text)
#create vpn connection using transit gateway
aws ec2 create-vpn-connection --type ipsec.1 --customer-gateway-id $cgwid --transit-gateway-id $trangw --options "{\"StaticRoutesOnly\":true}"
#Find the transit gateway attachment ID #this needs work as multiple vpc attachments need to be tagged and then queried before using here
trangwAttid=$(aws ec2 describe-transit-gateway-attachments --filter "Name=transit-gateway-id,Values=$trangw" --query "TransitGatewayAttachments[0].TransitGatewayAttachmentId" --output text)
trangwvpnAttid="tgw-attach-07ba1a1d5f277c387"
trangwvpcw1Attid="tgw-attach-08e783f21cd2dad0e"
trangwvpcmAttid="tgw-attach-0dfb5e27f8281ef03"
=====================================================================
#configure vpn
#10.0.0.0/16 -- AWS ENV
#10.2.0.0/16 -- On Prem

#login to the openswan server
ssh -A ec2-user@vpnservIP

sudo yum install openswan -y #Install openswan
sudo cat /etc/ipsec.conf #check last line status should be uncommented (include /etc/ipsec.d/*.conf)
sudo nano /etc/ipsec.d/connection.conf
conn VpnConn1
 authby=secret
 auto=start
 left=%defaultroute
 leftid=18.191.234.46 #leftid=cgwip (#3 TunnelInterfaceConfig: Outside IP Addresses: Customer Gateway)
 right=3.137.44.239 #right=vpgwip (#3 TunnelInterfaceConfig: Outside IP Addresses: Virtual Private Gateway)
 type=tunnel
 ikelifetime=8h
 keylife=1h
 phase2alg=aes128-sha1;modp1024
 ike=aes128-sha1;modp1024
 keyingtries=%forever
 keyexchange=ike
 leftsubnet=10.2.0.0/24
 rightsubnet=10.0.0.0/24
 dpddelay=10
 dpdtimeout=30
 dpdaction=restart_by_peer

sudo nano /etc/ipsec.d/connections.secrets
18.191.234.46 3.137.44.239: PSK "KZPCAYht3hzlCxkGwwsj8GA8ZhLlOsW6"
#cgw-ip vgw-ip: PSK "PRE_SHARED_KEY"

sudo nano /etc/sysctl.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.default.accept_source_route = 0

sudo systemctl restart network #service network restart then #sudo chkconfig ipsec on
sudo systemctl start ipsec #sudo service ipsec start
sudo systemctl status ipsec
=====================================================================
#post above changes, successful outcome can be measured by: 
aws ec2 describe-vpn-connections --query "VpnConnections[0].VgwTelemetry[0]"
#{
#    "AcceptedRouteCount": 0,
#    "LastStatusChange": "2020-07-18T13:37:26+00:00",
#    "OutsideIpAddress": "3.137.44.239",
#    "Status": "UP",
#    "StatusMessage": ""
#}
=====================================================================
#Insert route to vpn through Transit Gatewy into msubrtb
aws ec2 create-route --route-table-id $msubrtb --destination-cidr-block $opsubcidr --gateway-id $trangw
#Insert route to vpn through Transit Gatewy into w1subrtb
aws ec2 create-route --route-table-id $w1subrtb --destination-cidr-block $opsubcidr --gateway-id $trangw
=====================================================================
=====================================================================
#Experiment from here
=====================================================================
=====================================================================

#modify ingress rules for vpn ec2
aws ec2 authorize-security-group-ingress --group-id $sshopsgid --protocol tcp --port 22 --cidr $mypubip/32
aws ec2 describe-security-group --group-name sshopsgid

aws ec2 authorize-security-group-ingress --group-id $sshopsgid --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$msubcidr}]

mvpccidr="10.0.0.0/16"
msubcidr="10.0.0.0/24"
opvpccidr="10.2.0.0/16"
opsubcidr="10.2.0.0/24"

msgid=$(aws ec2 create-security-group --group-name msg --description "Security group for master" --vpc-id $mastervpc | jq '.GroupId' | tr -d '"')
aws ec2 authorize-security-group-ingress --group-id $msgid --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$opsubcidr}]

mserverid=$(aws ec2 run-instances --image-id ami-016b213e65284e9c9 --count 1 --instance-type t2.micro --key-name eastuskp --subnet-id $msub --security-group-ids $msgid --query 'Instances[0].InstanceId' --output text)
aws ec2 create-tags --resources $mserverid --tags Key=Name,Value=mserver