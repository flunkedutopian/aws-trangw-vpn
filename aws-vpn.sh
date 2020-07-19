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


#Create VPC, Subnet, Routetable, associate Route table with subnet - awsvpc
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
sshopsgid=$(aws ec2 create-security-group --group-name opvpnserversg --description "Security group for SSH access to op vpnserver" --vpc-id $onpremvpc | jq '.GroupId' | tr -d '"')
aws ec2 create-tags --resources $sshopsgid --tags Key=Name,Value=sshopsgid
#enable ssh from my pub ip
aws ec2 authorize-security-group-ingress --group-id $sshopsgid --protocol tcp --port 22 --cidr $mypubip/32

#Create an ec2 instance in op subnet to host openvpn
opserverid=$(aws ec2 run-instances --image-id ami-016b213e65284e9c9 --count 1 --instance-type t2.micro --key-name eastuskp --security-group-ids $sshopsgid --subnet-id $opsub --associate-public-ip-address --query 'Instances[0].InstanceId' --output text)
aws ec2 modify-instance-attribute --instance-id $opserverid --no-source-dest-check
aws ec2 create-tags --resources $opserverid --tags Key=Name,Value=opserverid
#check of previous instance with same name tag is existent or not, based on that change the reservation index
vpnservIP=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=opserverid" --query 'Reservations[1].Instances[0].NetworkInterfaces[0].PrivateIpAddresses[0].Association.PublicIp' --output text)

#on aws vpc:
cgwid=$(aws ec2 create-customer-gateway --bgp-asn 65000 --type ipsec.1 --public-ip $vpnservIP --query 'CustomerGateway.CustomerGatewayId' --output text)
aws ec2 create-tags --resources $cgwid --tags Key=Name,Value=cgw
#create tgw
trangwid=$(aws ec2 create-transit-gateway --description hubtrangw ^
    --options=AmazonSideAsn=64516,AutoAcceptSharedAttachments=enable,DefaultRouteTableAssociation=enable,DefaultRouteTablePropagation=enable,VpnEcmpSupport=enable,DnsSupport=enable ^
	--query "TransitGateway.TransitGatewayId" --output text

# or use this
# trangwid=$(aws ec2 create-transit-gateway --description hubtrangw --options=AmazonSideAsn=64516,AutoAcceptSharedAttachments=enable,DefaultRouteTableAssociation=enable,DefaultRouteTablePropagation=enable,VpnEcmpSupport=enable,DnsSupport=enable | jq '.TransitGateway.TransitGatewayId' | tr -d '"')

aws ec2 create-tags --resources $trangwid --tags Key=Name,Value=trangw
aws ec2 describe-transit-gateways --filter "Name=tag:Name,Values=trangw" --query "TransitGateways[0].State" --output text
hubtgwrtbid=$(aws ec2 describe-transit-gateways --filter "Name=tag:Name,Values=trangw" --query "TransitGateways[0].Options.AssociationDefaultRouteTableId" --output text)
hubtgwattid=$(aws ec2 describe-transit-gateway-attachments --filter "Name=transit-gateway-id,Values=$trangwid" --query "TransitGatewayAttachments[0].TransitGatewayAttachmentId" --output text)
#create vpn connection using transit gateway
aws ec2 create-vpn-connection --type ipsec.1 --customer-gateway-id $cgwid --transit-gateway-id $trangwid --options "{\"StaticRoutesOnly\":true}"
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
 leftid=18.188.159.101 #leftid=cgwip (#3 TunnelInterfaceConfig: Outside IP Addresses: Customer Gateway)
 right=18.189.146.248 #right=vpgwip (#3 TunnelInterfaceConfig: Outside IP Addresses: Virtual Private Gateway)
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
18.188.159.101 18.189.146.248: PSK "ukBRX_X6qK3tN8XPYO92NWk7.DEjbpfX"
#cgw-ip vgw-ip: PSK "PRE_SHARED_KEY"

sudo nano /etc/sysctl.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.default.accept_source_route = 0

sudo systemctl restart network #service network restart then #sudo chkconfig ipsec on
sudo systemctl start ipsec #sudo service ipsec start
sudo systemctl status ipsec
----------------------------------------------------------------------------------------------------------------------------------------------------
#Create route entries pointing to each other i.e. from aws-> on prem and from on-prem to aws
aws ec2 create-route --route-table-id $awssubrtb --destination-cidr-block $opsubcidr --gateway-id $trangwid
aws ec2 create-route --route-table-id $opsubrtb --destination-cidr-block $awssubcidr --gateway-id $trangwid

aws ec2 create-transit-gateway-route --destination-cidr-block $opsubcidr --transit-gateway-route-table-id $hubtgwrtbid --transit-gateway-attachment-id $hubtgwattid

#Create secgroup for ssh and launch instance - aws
awsec2sgid=$(aws ec2 create-security-group --group-name awsec2accesssg --description "Security group aws ec2 access" --vpc-id $awsvpc | jq '.GroupId' | tr -d '"')
aws ec2 authorize-security-group-ingress --group-id $sshawssgid --protocol tcp --port 22 --cidr $opsubcidr
aws ec2 run-instances --image-id ami-016b213e65284e9c9 --count 1 --instance-type t2.micro --key-name eastuskp --security-group-ids $sshawssgid --subnet-id $awssub


