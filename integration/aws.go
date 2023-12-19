package integration

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
)

// AWS checks that the user's AWS infra is SOC2 compliant
type AWS struct {
	IAM *IAM
	S3  *S3
	VPC *VPC
}

// New returns a new AWS integration
func NewAWS(region string) (*AWS, error) {
	s, err := session.NewSession(aws.NewConfig().WithRegion(region))
	if err != nil {
		return nil, err
	}

	return &AWS{IAM: NewIAM(s), S3: NewS3(s), VPC: NewVPC(s)}, nil
}

// Check checks that the user's AWS infra is SOC2 compliant
func (a *AWS) Check() ([]Result, error) {
	iamRes, err := a.IAM.Check()
	if err != nil {
		return nil, err
	}

	s3Res, err := a.S3.Check()
	if err != nil {
		return nil, err
	}

	vpcRes, err := a.VPC.Check()
	if err != nil {
		return nil, err
	}

	return concatSlice(iamRes, s3Res, vpcRes), nil
}

// IAM checks that the user's IAM infra is SOC2 compliant
type IAM struct {
	iamAPI *iam.IAM
}

// NewIAM returns a new IAM integration
func NewIAM(s *session.Session) *IAM {
	return &IAM{iamAPI: iam.New(s)}
}

// Check checks that the user's IAM infra is SOC2 compliant
func (i *IAM) Check() ([]Result, error) {
	mfaRes, err := i.checkConsoleMFA()
	if err != nil {
		return nil, err
	}

	staleCredsRes, err := i.checkIAMUsersUnusedCreds()
	if err != nil {
		return nil, err
	}

	rootMfaRes, err := i.checkRootAccountMFA()
	if err != nil {
		return nil, err
	}

	rootAccessKeysRes, err := i.checkRootAccountAccessKeys()
	if err != nil {
		return nil, err
	}

	adminPolicyRes, err := i.checkPolicyNoStatementsWithAdminAccess()
	if err != nil {
		return nil, err
	}

	userPolicyRes, err := i.checkNoUserPolicies()
	if err != nil {
		return nil, err
	}

	return concatSlice(
		mfaRes,
		staleCredsRes,
		rootMfaRes,
		rootAccessKeysRes,
		adminPolicyRes,
		userPolicyRes,
	), nil
}

// checkConsoleMFA checks that IAM users with console access have MFA enabled
func (i *IAM) checkConsoleMFA() ([]Result, error) {
	var mfaRes []Result
	rule := "IAM users with console access must have MFA enabled"

	users, err := i.iamAPI.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}

	for _, user := range users.Users {
		mfa, err := i.iamAPI.ListMFADevices(&iam.ListMFADevicesInput{UserName: user.UserName})
		if err != nil {
			return nil, err
		}

		_, err = i.iamAPI.GetLoginProfile(&iam.GetLoginProfileInput{UserName: user.UserName})
		if err != nil {
			mfaRes = append(
				mfaRes,
				i.userResult(aws.StringValue(user.Arn), rule, true, "User does not have console access"),
			)
			continue
		}

		if mfa.MFADevices == nil {
			mfaRes = append(
				mfaRes,
				i.userResult(aws.StringValue(user.Arn), rule, false, "User does not have MFA enabled"),
			)
		} else {
			mfaRes = append(mfaRes, i.userResult(aws.StringValue(user.Arn), rule, true, ""))
		}
	}

	return mfaRes, nil
}

// checkIAMUsersUnusedCreds checks that IAM users have no unused credentials
func (i *IAM) checkIAMUsersUnusedCreds() ([]Result, error) {
	var staleCredsRes []Result
	rule := "IAM users must not have credentials unused in the last 90 days"

	users, err := i.iamAPI.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}
	for _, user := range users.Users {
		accessKeys, err := i.iamAPI.ListAccessKeys(
			&iam.ListAccessKeysInput{UserName: user.UserName})
		if err != nil {
			return nil, err
		}

		for _, accessKey := range accessKeys.AccessKeyMetadata {
			if aws.StringValue(accessKey.Status) != "Active" {
				continue
			}

			out, err := i.iamAPI.GetAccessKeyLastUsed(
				&iam.GetAccessKeyLastUsedInput{AccessKeyId: accessKey.AccessKeyId})
			if err != nil {
				return nil, err
			}
			if out.AccessKeyLastUsed.LastUsedDate != nil && out.AccessKeyLastUsed.LastUsedDate.AddDate(0, 0, 90).Before(time.Now()) {
				staleCredsRes = append(
					staleCredsRes,
					i.userResult(aws.StringValue(user.Arn), rule, false, "User has credentials unused for more than 90 days"),
				)
			} else {
				staleCredsRes = append(staleCredsRes, i.userResult(aws.StringValue(user.Arn), rule, true, ""))
			}
		}
	}

	return staleCredsRes, nil
}

// checkRootAccountMFA checks that the root account has MFA enabled
func (i *IAM) checkRootAccountMFA() ([]Result, error) {
	rule := "Root account must have MFA enabled"

	root, err := i.iamAPI.GetAccountSummary(&iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}

	if aws.Int64Value(root.SummaryMap["AccountMFAEnabled"]) == 0 {
		return []Result{i.userResult("root", rule, false, "Root account does not have MFA enabled")}, nil
	}

	return []Result{i.userResult("root", rule, true, "")}, nil
}

// checkRootAccountAccessKeys checks that the root account has no access keys
func (i *IAM) checkRootAccountAccessKeys() ([]Result, error) {
	rule := "Root account must not have access keys"

	root, err := i.iamAPI.GetAccountSummary(&iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}

	if aws.Int64Value(root.SummaryMap["AccountAccessKeysPresent"]) != 0 {
		return []Result{i.userResult("root", rule, false, "Root account has access keys")}, nil
	}

	return []Result{i.userResult("root", rule, true, "")}, nil
}

// checkPolicyNoStatementsWithAdminAccess checks that there are no policy
// statements with admin access
func (i *IAM) checkPolicyNoStatementsWithAdminAccess() ([]Result, error) {
	var statementsRes []Result
	rule := "IAM policies must not have statements with admin access"

	policies, err := i.iamAPI.ListPolicies(
		&iam.ListPoliciesInput{Scope: aws.String("Local")},
	)
	if err != nil {
		return nil, err
	}

NEXTPOLICY:
	for _, policy := range policies.Policies {
		defaultVer, err := i.iamAPI.GetPolicyVersion(
			&iam.GetPolicyVersionInput{
				PolicyArn: policy.Arn,
				VersionId: policy.DefaultVersionId,
			})
		if err != nil {
			return nil, err
		}

		defaultVerJSON, err := url.QueryUnescape(aws.StringValue(defaultVer.PolicyVersion.Document))
		if err != nil {
			return nil, err
		}

		var policyDoc map[string]interface{}
		err = json.NewDecoder(strings.NewReader(defaultVerJSON)).Decode(&policyDoc)
		if err != nil {
			return nil, err
		}

		statements := policyDoc["Statement"].([]interface{})
		for _, statement := range statements {
			statementMap := statement.(map[string]interface{})
			isEffectAllow := statementMap["Effect"].(string) == "Allow"
			isActionAdmin := statementMap["Action"] == "*"
			isResourceAdmin := statementMap["Resource"] == "*"
			if isEffectAllow && isActionAdmin && isResourceAdmin {
				statementsRes = append(
					statementsRes,
					i.policyResult(aws.StringValue(policy.Arn), rule, false, "Policy has statement with admin access"),
				)
				continue NEXTPOLICY
			}
		}

		statementsRes = append(statementsRes, i.policyResult(aws.StringValue(policy.Arn), rule, true, ""))
	}

	return statementsRes, nil
}

// checkNoUserPolicies checks that no users have policies attached
func (i *IAM) checkNoUserPolicies() ([]Result, error) {
	var userPoliciesRes []Result
	rule := "IAM users must not have policies attached"

	users, err := i.iamAPI.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}

	for _, user := range users.Users {
		userPolicies, err := i.iamAPI.ListUserPolicies(
			&iam.ListUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			return nil, err
		}
		if len(userPolicies.PolicyNames) > 0 {
			userPoliciesRes = append(userPoliciesRes, i.userResult(aws.StringValue(user.UserName), rule, false, "User has inline policies attached"))
			continue
		}

		attachedPolicies, err := i.iamAPI.ListAttachedUserPolicies(
			&iam.ListAttachedUserPoliciesInput{UserName: user.UserName})
		if err != nil {
			return nil, err
		}
		if len(attachedPolicies.AttachedPolicies) > 0 {
			userPoliciesRes = append(userPoliciesRes, i.userResult(aws.StringValue(user.UserName), rule, false, "User has managed policies attached"))
			continue
		}

		userPoliciesRes = append(userPoliciesRes, i.userResult(aws.StringValue(user.UserName), rule, true, ""))
	}

	return userPoliciesRes, nil
}

func (i *IAM) userResult(name, rule string, compliant bool, reason string) Result {
	return Result{
		Resource: Resource{
			Type: "aws/iam-user",
			Name: name,
		},
		Rule:      rule,
		Compliant: compliant,
		Reason:    reason,
	}
}

func (i *IAM) policyResult(name, rule string, compliant bool, reason string) Result {
	return Result{
		Resource: Resource{
			Type: "aws/iam-policy",
			Name: name,
		},
		Rule:      rule,
		Compliant: compliant,
		Reason:    reason,
	}
}

// S3 checks that the user's IAM infra is SOC2 compliant
type S3 struct {
	s3API *s3.S3
}

// NewS3 returns a new S3 integration
func NewS3(s *session.Session) *S3 {
	return &S3{s3API: s3.New(s)}
}

// Check checks that the user's S3 infra is SOC2 compliant
func (s *S3) Check() ([]Result, error) {
	return s.checkS3BucketEncryption()
}

// checkS3BucketEncryption checks that S3 buckets are encrypted
func (s *S3) checkS3BucketEncryption() ([]Result, error) {
	var s3Res []Result
	rule := "S3 buckets must be encrypted"

	buckets, err := s.s3API.ListBuckets(nil)
	if err != nil {
		return nil, err
	}

	for _, bucket := range buckets.Buckets {
		bucketLoc, err := s.s3API.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: bucket.Name})
		if err != nil {
			return nil, err
		}

		region := aws.StringValue(bucketLoc.LocationConstraint)
		if len(region) == 0 {
			// Buckets in Region us-east-1 have a LocationConstraint of null.
			region = "us-east-1"
		}

		regionSession := session.Must(
			session.NewSession(
				aws.NewConfig().WithRegion(region)))
		regionS3API := s3.New(regionSession)

		encryption, err := regionS3API.GetBucketEncryption(
			&s3.GetBucketEncryptionInput{Bucket: bucket.Name})
		if err != nil {
			return nil, err
		}

		if encryption.ServerSideEncryptionConfiguration == nil {
			s3Res = append(
				s3Res,
				s.bucketResult(bucket, rule, false, "Bucket is not encrypted"),
			)
		} else {
			s3Res = append(s3Res, s.bucketResult(bucket, rule, true, ""))
		}
	}

	return s3Res, nil
}

func (s *S3) bucketResult(bucket *s3.Bucket, rule string, compliant bool, reason string) Result {
	return Result{
		Resource: Resource{
			Type: "aws/s3-bucket",
			Name: aws.StringValue(bucket.Name),
		},
		Rule:      rule,
		Compliant: compliant,
		Reason:    reason,
	}
}

// VPC checks that the user's VPCs are SOC2 compliant
type VPC struct {
	ec2API *ec2.EC2
}

// NewVPC returns a new VPC integration
func NewVPC(s *session.Session) *VPC {
	return &VPC{ec2API: ec2.New(s)}
}

// Check checks that the user's VPCs are SOC2 compliant
func (v *VPC) Check() ([]Result, error) {
	return v.checkVPCFlowLogs()
}

// checkVPCFlowLogs checks that VPC flow logs are enabled
func (v *VPC) checkVPCFlowLogs() ([]Result, error) {
	var vpcRes []Result
	rule := "VPC flow logs must be enabled"

	// use describe-region api to list all regions
	regions, err := v.ec2API.DescribeRegions(nil)
	if err != nil {
		return nil, err
	}

	for _, region := range regions.Regions {
		regionSession := session.Must(
			session.NewSession(
				aws.NewConfig().WithRegion(aws.StringValue(region.RegionName))))
		regionEC2API := ec2.New(regionSession)

		vpcs, err := regionEC2API.DescribeVpcs(nil)
		if err != nil {
			return nil, err
		}

		for _, vpc := range vpcs.Vpcs {
			flowLogs, err := regionEC2API.DescribeFlowLogs(
				&ec2.DescribeFlowLogsInput{Filter: []*ec2.Filter{
					{
						Name:   aws.String("resource-id"),
						Values: []*string{vpc.VpcId},
					},
				}})
			if err != nil {
				return nil, err
			}

			if len(flowLogs.FlowLogs) == 0 {
				vpcRes = append(
					vpcRes,
					v.vpcResult(vpc, rule, false, "VPC flow logs are not enabled"),
				)
			} else {
				vpcRes = append(vpcRes, v.vpcResult(vpc, rule, true, ""))
			}
		}
	}

	return vpcRes, nil
}

func (v *VPC) vpcResult(vpc *ec2.Vpc, rule string, compliant bool, reason string) Result {
	return Result{
		Resource: Resource{
			Type: "aws/vpc",
			Name: aws.StringValue(vpc.VpcId),
		},
		Rule:      rule,
		Compliant: compliant,
		Reason:    reason,
	}
}
