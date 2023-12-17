package integration

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

// AWS checks that the user's AWS infra is SOC2 compliant
type AWS struct {
	IAM *IAM
}

// New returns a new AWS integration
func NewAWS() (*AWS, error) {
	s, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	return &AWS{IAM: NewIAM(s)}, nil
}

// Check checks that the user's AWS infra is SOC2 compliant
func (a *AWS) Check() ([]Result, error) {
	return a.IAM.Check()
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
