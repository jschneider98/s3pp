package s3pp

import (
	"errors"
	"time"
)

//
type AwsPostPolicyOptions struct {
	Id string
	Secret string
	Bucket string
	Region string
	Duration time.Duration
}

//
func CreateAwsPostPolicyOptions (id string, secret string, bucket string, region string, duration time.Duration) (*AwsPostPolicyOptions) {

	options := &AwsPostPolicyOptions{
		id,
		secret,
		bucket,
		region,
		duration,
	}

	return options
}

//
func (o *AwsPostPolicyOptions) IsValid() error {
	isValid := true
	err := "Invalid AWS Post Policy options:"

	if o.Id == "" {
		err += " Invalid Id."
		isValid = false
	}

	if o.Secret == "" {
		err += " Invalid Secrect."
		isValid = false
	}

	if o.Bucket == "" {
		err += " Invalid Bucket."
		isValid = false
	}

	if o.Region == "" {
		err += " Invalid Region."
		isValid = false
	}

	if o.Duration == 0 {
		err += " Invalid Duration."
		isValid = false
	}

	if !isValid {
		return errors.New(err)
	}

	return nil
}
