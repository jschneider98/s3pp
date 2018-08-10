package s3pp

import (
	"testing"
	"time"
	"fmt"
)

var testPolicy *AwsPostPolicy

//
func setTestPolicy() (*AwsPostPolicy) {
	var err error

	if testPolicy != nil {
		return testPolicy
	}

	now := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	later := now.Add(time.Minute)

	options := CreateAwsPostPolicyOptions(
		"aws-id",
		"aws-secret",
		"aws-bucket",
		"aws-region",
		time.Minute,
	)

	testPolicy, err = CreateAwsPostPolicy(options)

	if err != nil {
		panic("Failed to create test policy")
	}

	testPolicy.Expiration = later.Format(time.RFC3339)
	testPolicy.dateStamp = now.Format("20060102")

	return testPolicy
}

//
func TestGetJsonPolicy(t *testing.T) {
	setTestPolicy()

	policy, err := testPolicy.GetJsonPolicy()

	if err != nil {
		t.Error(err)
	}

	fmt.Println(string(policy[:]))
}

//
func TestGetBase64Policy(t *testing.T) {
	setTestPolicy()

	policy, err := testPolicy.GetBase64Policy()

	if err != nil {
		t.Error(err)
	}

	fmt.Println(policy)
}

//
func TestHmacSha256(t *testing.T) {
	setTestPolicy()

	hash := testPolicy.HmacSha256([]byte("key"), []byte("data"))
	match := []byte{80, 49, 254, 61, 152, 156, 109, 21, 55, 160, 19, 250, 110, 115, 157, 162, 52, 99, 253, 174, 195, 183, 1, 55, 216, 40, 227, 106, 206, 34, 27, 208}

	if (string(hash) != string(match)) {
		t.Errorf("Hash mismatch. Expected: '%v' Got: '%v'\n", match, hash)
	}
}

//
func TestGetS3SignatureKey(t *testing.T) {
	setTestPolicy()

	hash := testPolicy.GetS3SignatureKey()
	match := []byte{24, 197, 170, 253, 7, 13, 35, 65, 255, 180, 168, 133, 14, 15, 155, 251, 143, 226, 131, 205, 219, 18, 235, 154, 81, 84, 117, 136, 49, 63, 210, 240}

	if (string(hash) != string(match)) {
		t.Errorf("Hash mismatch. Expected: '%v' Got: '%v'\n", match, hash)
	}
}

//
func TestGetS3Signature(t *testing.T) {
	setTestPolicy()

	hash, err := testPolicy.GetS3Signature()

	if err != nil {
		t.Error(err)
	}

	match := ""

	if (string(hash) != string(match)) {
		t.Errorf("Hash mismatch. Expected: '%v' Got: '%v'\n", match, hash)
	}
}

//
func TestSetCondition(t *testing.T) {
	setTestPolicy()

	orig := [3]string{"eq", "$key", "user/"}

	new := testPolicy.SetCondition(orig[0], "key", orig[2])

	if new != orig {
		t.Errorf("Array mismatch. Expected: '%v' Got: '%v'\n", orig, new)
	}
}
