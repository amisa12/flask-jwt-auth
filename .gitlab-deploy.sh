#!/bin/bash

#Get servers list
set -f
#DEPLOY_SERVERS=18.224.71.177
string=$DEPLOY_SERVERS
array=(${string//,/ })

#Iterate servers for deploy and pull last commit
for i in "${!array[@]}";do   
	echo "Deploy project on server ${array[i]}"    
	ssh ec2-user@${array[i]} "sudo mkdir -p /var/log/authentication && sudo rm -rf /apps/authentication && sudo mkdir -p /apps/authentication && sudo chown -R ec2-user.ec2-user /apps/authentication  && cd /apps/authentication && git clone https://$CI_DEPLOY_USER:$CI_DEPLOY_PASSWORD@gitlab.com/farmdrive/laas/authentication.git"
done

