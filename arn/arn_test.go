package arn

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

var validARNs = []string{
	"arn:aws:apigateway:us-east-1::/restapis/a123456789012bc3de45678901f23a45/*",
	"arn:aws:apigateway:us-east-1::a123456789012bc3de45678901f23a45:/test/mydemoresource/*",
	"arn:aws:apigateway:*::a123456789012bc3de45678901f23a45:/*/petstorewalkthrough/pets",
	"arn:aws:execute-api:us-east-1:123456789012:qsxrty/test/GET/mydemoresource/*",
	"arn:aws:artifact:::report-package/Certifications and Attestations/SOC/*",
	"arn:aws:artifact:::report-package/Certifications and Attestations/ISO/*",
	"arn:aws:artifact:::report-package/Certifications and Attestations/PCI/*",
	"arn:aws:autoscaling:us-east-1:123456789012:scalingPolicy:c7a27f55-d35e-4153-b044-8ca9155fc467:autoScalingGroupName/my-test-asg1:policyName/my-scaleout-policy",
	"arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
	"arn:aws:cloudformation:us-east-1:123456789012:stack/MyProductionStack/abc9dbf0-43c2-11e3-a6e8-50fa526be49c",
	"arn:aws:cloudformation:us-east-1:123456789012:changeSet/MyProductionChangeSet/abc9dbf0-43c2-11e3-a6e8-50fa526be49c",
	"arn:aws:cloudsearch:us-east-1:123456789012:domain/imdb-movies",
	"arn:aws:cloudtrail:us-east-1:123456789012:trail/mytrailname",
	"arn:aws:events:us-east-1:*:*",
	"arn:aws:events:us-east-1:123456789012:*",
	"arn:aws:events:us-east-1:123456789012:rule/my-rule",
	"arn:aws:logs:us-east-1:*:*",
	"arn:aws:logs:us-east-1:123456789012:*",
	"arn:aws:logs:us-east-1:123456789012:log-group:my-log-group",
	"arn:aws:logs:us-east-1:123456789012:log-group:my-log-group:*",
	"arn:aws:logs:us-east-1:123456789012:log-group:my-log-group*",
	"arn:aws:logs:us-east-1:123456789012:log-group:my-log-group:log-stream:my-log-stream",
	"arn:aws:logs:us-east-1:123456789012:log-group:my-log-group:log-stream:my-log-stream*",
	"arn:aws:logs:us-east-1:123456789012:log-group:my-log-group*:log-stream:my-log-stream*",
	"arn:aws:codebuild:us-east-1:123456789012:project/my-demo-project",
	"arn:aws:codebuild:us-east-1:123456789012:build/my-demo-project:7b7416ae-89b4-46cc-8236-61129df660ad",
	"arn:aws:codecommit:us-east-1:123456789012:MyDemoRepo",
	"arn:aws:codedeploy:us-east-1:123456789012:application:WordPress_App",
	"arn:aws:codedeploy:us-east-1:123456789012:instance/AssetTag*",
	"arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1:1a1a1a1a-ffff-1111-9999-12345678",
	"arn:aws:cognito-identity:us-east-1:123456789012:/identitypool/us-east-1:1a1a1a1a-ffff-1111-9999-12345678",
	"arn:aws:cognito-sync:us-east-1:123456789012:identitypool/us-east-1:1a1a1a1a-ffff-1111-9999-12345678",
	"arn:aws:config:us-east-1:123456789012:config-rule/MyConfigRule",
	"arn:aws:codepipeline:us-east-1:123456789012:MyDemoPipeline",
	"arn:aws:codestar:us-east-1:123456789012:my-first-projec",
	"arn:aws:directconnect:us-east-1:123456789012:dxcon/dxcon-fgase048",
	"arn:aws:directconnect:us-east-1:123456789012:dxlag/dxlag-ffy7zraq",
	"arn:aws:directconnect:us-east-1:123456789012:dxvif/dxvif-fgrb110x",
	"arn:aws:dynamodb:us-east-1:123456789012:table/books_table",
	"arn:aws:ecr:us-east-1:123456789012:repository/my-repository",
	"arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster",
	"arn:aws:ecs:us-east-1:123456789012:container-instance/403125b0-555c-4473-86b5-65982db28a6d",
	"arn:aws:ecs:us-east-1:123456789012:task-definition/hello_world:8",
	"arn:aws:ecs:us-east-1:123456789012:service/sample-webapp",
	"arn:aws:ecs:us-east-1:123456789012:task/1abf0f6d-a411-4033-b8eb-a4eed3ad252a",
	"arn:aws:ecs:us-east-1:123456789012:container/476e7c41-17f2-4c17-9d14-412566202c8a",
	"arn:aws:ec2:us-east-1:123456789012:dedicated-host/h-12345678",
	"arn:aws:ec2:us-east-1::image/ami-1a2b3c4d",
	"arn:aws:ec2:us-east-1:123456789012:instance/*",
	"arn:aws:ec2:us-east-1:123456789012:volume/*",
	"arn:aws:ec2:us-east-1:123456789012:volume/vol-1a2b3c4d",
	"arn:aws:elasticbeanstalk:us-east-1:123456789012:application/My App",
	"arn:aws:elasticbeanstalk:us-east-1:123456789012:applicationversion/My App/My Version",
	"arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/My App/MyEnvironment",
	"arn:aws:elasticbeanstalk:us-east-1::solutionstack/32bit Amazon Linux running Tomcat 7",
	"arn:aws:elasticbeanstalk:us-east-1:123456789012:configurationtemplate/My App/My Template",
	"arn:aws:elasticfilesystem:us-east-1:123456789012:file-system-id/fs12345678",
	"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-load-balancer/50dc6c495c0c9188",
	"arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-load-balancer/50dc6c495c0c9188/f2f7dc8efc522ab2",
	"arn:aws:elasticloadbalancing:us-east-1:123456789012:listener-rule/app/my-load-balancer/50dc6c495c0c9188/f2f7dc8efc522ab2/9683b2d02a6cabee",
	"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/73e2d6bc24d8a067",
	"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/my-load-balancer",
	"arn:aws:elastictranscoder:us-east-1:123456789012:preset/*",
	"arn:aws:elasticache:us-east-2:123456789012:cluster:myCluster",
	"arn:aws:elasticache:us-east-2:123456789012:snapshot:mySnapshot",
	"arn:aws:es:us-east-1:123456789012:domain/streaming-logs",
	"arn:aws:glacier:us-east-1:123456789012:vaults/examplevault",
	"arn:aws:glacier:us-east-1:123456789012:vaults/example*",
	"arn:aws:glacier:us-east-1:123456789012:vaults/*",
	"arn:aws:health:us-east-1::event/AWS_EC2_EXAMPLE_ID",
	"arn:aws:health:us-east-1:123456789012:entity/AVh5GGT7ul1arKr1sE1K",
	"arn:aws:iam::123456789012:root",
	"arn:aws:iam::123456789012:user/Bob",
	"arn:aws:iam::123456789012:user/division_abc/subdivision_xyz/Bob",
	"arn:aws:iam::123456789012:group/Developers",
	"arn:aws:iam::123456789012:group/division_abc/subdivision_xyz/product_A/Developers",
	"arn:aws:iam::123456789012:role/S3Access",
	"arn:aws:iam::123456789012:role/application_abc/component_xyz/S3Access",
	"arn:aws:iam::123456789012:policy/UsersManageOwnCredentials",
	"arn:aws:iam::123456789012:policy/division_abc/subdivision_xyz/UsersManageOwnCredentials",
	"arn:aws:iam::123456789012:instance-profile/Webserver",
	"arn:aws:sts::123456789012:federated-user/Bob",
	"arn:aws:sts::123456789012:assumed-role/Accounting-Role/Mary",
	"arn:aws:iam::123456789012:mfa/BobJonesMFA",
	"arn:aws:iam::123456789012:server-certificate/ProdServerCert",
	"arn:aws:iam::123456789012:server-certificate/division_abc/subdivision_xyz/ProdServerCert",
	"arn:aws:iam::123456789012:saml-provider/ADFSProvider",
	"arn:aws:iam::123456789012:oidc-provider/GoogleProvider",
	"arn:aws:iot:us-east-1:123456789012:cert/123a456b789c123d456e789f123a456b789c123d456e789f123a456b789c123c456d7",
	"arn:aws:iot:us-east-1:123456789012:rule/MyIoTRule",
	"arn:aws:iot:us-east-1:123456789012:client/client101",
	"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
	"arn:aws:kms:us-east-1:123456789012:alias/example-alias",
	"arn:aws:firehose:us-east-1:123456789012:deliverystream/example-stream-name",
	"arn:aws:kinesis:us-east-1:123456789012:stream/example-stream-name",
	"arn:aws:lambda:us-east-1:123456789012:function:ProcessKinesisRecords",
	"arn:aws:lambda:us-east-1:123456789012:function:ProcessKinesisRecords:alias",
	"arn:aws:lambda:us-east-1:123456789012:function:ProcessKinesisRecords:1.0",
	"arn:aws:lambda:us-east-1:123456789012:event-source-mappings:kinesis-stream-arn",
	"arn:aws:machinelearning:us-east-1:123456789012:datasource/my-datasource-1",
	"arn:aws:machinelearning:us-east-1:123456789012:mlmodel/my-mlmodel",
	"arn:aws:machinelearning:us-east-1:123456789012:batchprediction/my-batchprediction",
	"arn:aws:machinelearning:us-east-1:123456789012:evaluation/my-evaluation",
	"arn:aws:organizations:us-east-1:123456789012:organization/o-a1b2c3d4e5example",
	"arn:aws:organizations:us-east-1:123456789012:root/o-a1b2c3d4e5/r-f6g7h8i9j0example",
	"arn:aws:organizations:us-east-1:123456789012:account/o-a1b2c3d4e5/123456789012",
	"arn:aws:organizations:us-east-1:123456789012:ou/o-a1b2c3d4e5/ou-1a2b3c-k9l8m7n6o5example",
	"arn:aws:organizations:us-east-1:123456789012:policy/o-a1b2c3d4e5/service_control_policy/p-p4q3r2s1t0example",
	"arn:aws:organizations:us-east-1:123456789012:handshake/o-a1b2c3d4e5/h-u2v4w5x8y0example",
	"arn:aws:mobilehub:us-east-1:123456789012:project/a01234567-b012345678-123c-d013456789abc",
	"arn:aws:polly:us-east-1:123456789012:lexicon/myLexicon",
	"arn:aws:redshift:us-east-1:123456789012:cluster:my-cluster",
	"arn:aws:redshift:us-east-1:123456789012:my-cluster/my-dbuser-name",
	"arn:aws:redshift:us-east-1:123456789012:parametergroup:my-parameter-group",
	"arn:aws:redshift:us-east-1:123456789012:securitygroup:my-public-group",
	"arn:aws:redshift:us-east-1:123456789012:snapshot:my-cluster/my-snapshot20130807",
	"arn:aws:redshift:us-east-1:123456789012:subnetgroup:my-subnet-10",
	"arn:aws:rds:us-east-1:123456789012:db:mysql-db-instance1",
	"arn:aws:rds:us-east-1:123456789012:snapshot:my-snapshot2",
	"arn:aws:rds:us-east-1:123456789012:cluster:my-cluster1",
	"arn:aws:rds:us-east-1:123456789012:cluster-snapshot:cluster1-snapshot7",
	"arn:aws:rds:us-east-1:123456789012:og:mysql-option-group1",
	"arn:aws:rds:us-east-1:123456789012:pg:mysql-repl-pg1",
	"arn:aws:rds:us-east-1:123456789012:cluster-pg:aurora-pg3",
	"arn:aws:rds:us-east-1:123456789012:secgrp:dev-secgrp2",
	"arn:aws:rds:us-east-1:123456789012:subgrp:prod-subgrp1",
	"arn:aws:rds:us-east-1:123456789012:es:monitor-events2",
	"arn:aws:route53:::hostedzone/Z148QEXAMPLE8V",
	"arn:aws:route53:::change/C2RDJ5EXAMPLE2",
	"arn:aws:route53:::change/*",
	"arn:aws:ssm:us-east-1:123456789012:document/highAvailabilityServerSetup",
	"arn:aws:ssm:us-east-1:123456789012:parameter/myParameterName",
	"arn:aws:ssm:us-east-1:123456789012:patchbaseline/pb-12345678901234567",
	"arn:aws:ssm:us-east-1:123456789012:maintenancewindow/mw-12345678901234567",
	"arn:aws:ssm:us-east-1:123456789012:automation-execution/123456-6789-1a2b3-c4d5-e1a2b3c4d",
	"arn:aws:ssm:us-east-1:123456789012:automation-activity/myActivityName",
	"arn:aws:ssm:us-east-1:123456789012:automation-definition/myDefinitionName:1",
	"arn:aws:ssm:us-east-1:123456789012:managed-instance/mi-12345678901234567",
	"arn:aws:ssm:us-east-1:123456789012:managed-instance-inventory/i-12345661",
	"arn:aws:sns:*:123456789012:my_corporate_topic",
	"arn:aws:sns:us-east-1:123456789012:my_corporate_topic:02034b43-fefa-4e07-a5eb-3be56f8c54ce",
	"arn:aws:sqs:us-east-1:123456789012:queue1",
	"arn:aws:s3:::my_corporate_bucket",
	"arn:aws:s3:::my_corporate_bucket/exampleobject.png",
	"arn:aws:s3:::my_corporate_bucket/*",
	"arn:aws:s3:::my_corporate_bucket/Development/*",
	"arn:aws:swf:us-east-1:123456789012:/domain/department1",
	"arn:aws:swf:*:123456789012:/domain/*",
	"arn:aws:states:us-east-1:123456789012:activity:HelloActivity",
	"arn:aws:states:us-east-1:123456789012:stateMachine:HelloStateMachine",
	"arn:aws:states:us-east-1:123456789012:execution:HelloStateMachine:HelloStateMachineExecution",
	"arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B",
	"arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B/volume/vol-1122AABB",
	"arn:aws:storagegateway:us-east-1:123456789012:tape/AMZNC8A26D",
	"arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B/target/iqn.1997-05.com.amazon:vol-1122AABB",
	"arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B/device/AMZN_SGW-FF22CCDD_TAPEDRIVE_00010",
	"arn:aws:trustedadvisor:*:123456789012:checks/fault_tolerance/BueAdJ7NrP",
	"arn:aws:waf::123456789012:rule/41b5b052-1e4a-426b-8149-3595be6342c2",
	"arn:aws:waf-regional:us-east-1:123456789012:rule/41b5b052-1e4a-426b-8149-3595be6342c2",
	"arn:aws:waf::123456789012:webacl/3bffd3ed-fa2e-445e-869f-a6a7cf153fd3",
	"arn:aws:waf-regional:us-east-1:123456789012:webacl/3bffd3ed-fa2e-445e-869f-a6a7cf153fd3",
	"arn:aws:waf::123456789012:ipset/3f74bd8c-f046-4970-a1a7-41aa52e05480",
	"arn:aws:waf-regional:us-east-1:123456789012:ipset/3f74bd8c-f046-4970-a1a7-41aa52e05480",
	"arn:aws:waf::123456789012:bytematchset/d131bc0b-57be-4536-af1d-4894fd28acc4",
	"arn:aws:waf-regional:us-east-1:123456789012:bytematchset/d131bc0b-57be-4536-af1d-4894fd28acc4",
}

var invalidARNs = []string{
	"arn :aws:ec2:us-east-1:123456789012:volume/vol-1a2b3c4d",
	"arn:a ws:ec2:us-east-1:123456789012:volume/vol-1a2b3c4d",
	"arn:aws:ec2 :us-east-1:123456789012:volume/vol-1a2b3c4d",
	"arn:aws:ec2:us-east-1 :123456789012:volume/vol-1a2b3c4d",
	"arn:aws:ec2:us-east-1:123456789012 :volume/vol-1a2b3c4d",
	"arn:aws:ec2:us-east-1:123456789012:volume /vol-1a2b3c4d",
	"arn:aws:ec2:us-east-1:123456789012",
	"arn:awr:ec2:us-east-1:123456789012:volume/vol-1a2b3c4d",
	"arn::ec2:us-east-1:123456789012:volume/vol-1a2b3c4d",
	"arn:awr:ec2:us-east-1:123456789012:volume/vol-1a2b3c4d",
	"arn:aws::us-east-1:123456789012:volume/vol-1a2b3c4d",
	"arn:awr:ec2:notaregion:123456789012:volume/vol-1a2b3c4d",
	"arn:aws:ec2:us-east-1:12345678901:volume/vol-1a2b3c4d",
	"arn:aws:ec2:us-east-1:123F56789012:volume/vol-1a2b3c4d",
	"arn:aws:ec2:us-east-1:123.56789012:volume/vol-1a2b3c4d",
	":aws:ec2:us-east-1:123.56789012:volume/vol-1a2b3c4d",
	"arm:aws:ec2:us-east-1:123.56789012:volume/vol-1a2b3c4d",
}

func TestValid(t *testing.T) {
	for i, a := range validARNs {
		assert.True(t, Valid(a), fmt.Sprintf("Valid ARN failed test: %d - %s", i, a))
	}
	for i, a := range invalidARNs {
		assert.False(t, Valid(a), fmt.Sprintf("Invalid ARN failed test: %d - %s", i, a))
	}
}

func TestParse(t *testing.T) {
	arn := "arn:aws:ec2:us-east-1:123456789012:volume/vol-1a2b3c4d"
	a, err := Parse(arn)
	if err != nil {
		t.Fatalf("Error parsing arn")
	}
	assert.Equal(t, "aws", a.Partition, "Partition not as expect")
	assert.Equal(t, "ec2", a.Service, "Service not as expect")
	assert.Equal(t, "us-east-1", a.Region, "Region not as expect")
	assert.Equal(t, "123456789012", a.AccountID, "AccountID not as expect")
	assert.Equal(t, "volume", a.ResourceType, "ResourceType not as expect")
	assert.Equal(t, "/", a.resourceSep, "resourceSep not as expect")
	assert.Equal(t, "vol-1a2b3c4d", a.Resource, "resourceSep not as expect")
	assert.Equal(t, arn, a.String(), "String form of ARN not as expected")

	arn = "arn:aws:rds:us-east-1:123456789012:snapshot:my-snapshot2"
	a, err = Parse(arn)
	if err != nil {
		t.Fatalf("Error parsing arn")
	}
	assert.Equal(t, "aws", a.Partition, "Partition not as expect")
	assert.Equal(t, "rds", a.Service, "Service not as expect")
	assert.Equal(t, "us-east-1", a.Region, "Region not as expect")
	assert.Equal(t, "123456789012", a.AccountID, "AccountID not as expect")
	assert.Equal(t, "snapshot", a.ResourceType, "ResourceType not as expect")
	assert.Equal(t, ":", a.resourceSep, "resourceSep not as expect")
	assert.Equal(t, "my-snapshot2", a.Resource, "resourceSep not as expect")
	assert.Equal(t, arn, a.String(), "String form of ARN not as expected")

	arn = "arn:aws:s3:::my_corporate_bucket"
	a, err = Parse(arn)
	if err != nil {
		t.Fatalf("Error parsing arn")
	}
	assert.Equal(t, "aws", a.Partition, "Partition not as expect")
	assert.Equal(t, "s3", a.Service, "Service not as expect")
	assert.Equal(t, "", a.Region, "Region not as expect")
	assert.Equal(t, "", a.AccountID, "AccountID not as expect")
	assert.Equal(t, "", a.ResourceType, "ResourceType not as expect")
	assert.Equal(t, "", a.resourceSep, "resourceSep not as expect")
	assert.Equal(t, "my_corporate_bucket", a.Resource, "resourceSep not as expect")
	assert.Equal(t, arn, a.String(), "String form of ARN not as expected")
}
