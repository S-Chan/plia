package integration

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
)

// AWS checks that the user's AWS infra is SOC2 compliant
type AWS struct {
	IAM *IAM
	S3  *S3
}

// New returns a new AWS integration
func NewAWS() (*AWS, error) {
	// TODO: allow users to specify region
	s, err := session.NewSession(aws.NewConfig().WithRegion("us-east-1"))
	if err != nil {
		return nil, err
	}

	return &AWS{IAM: NewIAM(s), S3: NewS3(s)}, nil
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

	return append(iamRes, s3Res...), nil
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

	return append(mfaRes, staleCredsRes...), nil
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
				i.userResult(user, rule, true, "User does not have console access"),
			)
			continue
		}

		if mfa.MFADevices == nil {
			mfaRes = append(
				mfaRes,
				i.userResult(user, rule, false, "User does not have MFA enabled"),
			)
		} else {
			mfaRes = append(mfaRes, i.userResult(user, rule, true, ""))
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
					i.userResult(user, rule, false, "User has credentials unused for more than 90 days"),
				)
			} else {
				staleCredsRes = append(staleCredsRes, i.userResult(user, rule, true, ""))
			}
		}
	}

	return staleCredsRes, nil
}

func (i *IAM) userResult(user *iam.User, rule string, compliant bool, reason string) Result {
	return Result{
		Resource: Resource{
			Type: "aws/iam-user",
			Name: aws.StringValue(user.Arn),
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
