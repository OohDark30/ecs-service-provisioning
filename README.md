# ecs-service-provisioning 
--------------------------------------------------------------------------------------------------------------------
ecs-service-provisioning is a PYTHON based script that demonstrates how to provision object storage for external
clients.

ecs-service-provisioning utilizes the ECS Management REST APIs, SQLLite, and SMTP to retrieve service provisioning requests,
generate the necessary ECS namespace, IAM users / secrets, IAM Policies, and buckets. 

To get started do the following:
1. Use DB Browser for SQL Lite to update the single record in the `ecsservicerequests` table in the `ecsservicerequests.db` included in the project 
file to setup namespace, buckets, etc.  Make sure the status is set to "U" so that when the `ecs-service-provisioning.py` script is run the record will be picked up 
and processed.
2. Copy the ecs_service_provisioning_configuration.sample file in the configuration directory to ecs_service_provisioning_configuration.json in the same directory and update it
for your ECS environment.

For more information, please see the [wiki](https://github.com/OohDark30/ecs-service-provisioning/wiki)





