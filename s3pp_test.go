package s3pp

import (
	"testing"
	"time"
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

	testPolicy.SetCondition("eq", "acl", "private")
	testPolicy.SetCondition("eq", "key", "user/")

	return testPolicy
}

//
func TestGetJsonPolicy(t *testing.T) {
	setTestPolicy()

	policy, err := testPolicy.GetJsonPolicy()

	if err != nil {
		t.Error(err)
	}

	match := "{\"expiration\":\"2009-11-10T23:01:00Z\",\"conditions\":[[\"eq\",\"$bucket\",\"aws-bucket\"],[\"eq\",\"$acl\",\"private\"],[\"eq\",\"$key\",\"user/\"],[\"eq\",\"$x-amz-meta-uuid\",\"14365123651274\"],[\"eq\",\"$x-amz-credential\",\"aws-id/20091110/aws-region/s3/aws4_request\"],[\"eq\",\"$x-amz-algorithm\",\"AWS4-HMAC-SHA256\"],[\"eq\",\"$x-amz-date\",\"20091110T000000Z\"]]}"

	if string(policy[:]) != match {
		t.Errorf("Invalid JSON policy. Expected: '%v' Got: '%v'\n", match, string(policy[:]))
	}
}

//
func TestGetBase64Policy(t *testing.T) {
	setTestPolicy()

	policy, err := testPolicy.GetBase64Policy()

	if err != nil {
		t.Error(err)
	}

	match := "eyJleHBpcmF0aW9uIjoiMjAwOS0xMS0xMFQyMzowMTowMFoiLCJjb25kaXRpb25zIjpbWyJlcSIsIiRidWNrZXQiLCJhd3MtYnVja2V0Il0sWyJlcSIsIiRhY2wiLCJwcml2YXRlIl0sWyJlcSIsIiRrZXkiLCJ1c2VyLyJdLFsiZXEiLCIkeC1hbXotbWV0YS11dWlkIiwiMTQzNjUxMjM2NTEyNzQiXSxbImVxIiwiJHgtYW16LWNyZWRlbnRpYWwiLCJhd3MtaWQvMjAwOTExMTAvYXdzLXJlZ2lvbi9zMy9hd3M0X3JlcXVlc3QiXSxbImVxIiwiJHgtYW16LWFsZ29yaXRobSIsIkFXUzQtSE1BQy1TSEEyNTYiXSxbImVxIiwiJHgtYW16LWRhdGUiLCIyMDA5MTExMFQwMDAwMDBaIl1dfQ=="

	if policy != match {
		t.Errorf("Invalid base64Policy. Expected: '%v' Got: '%v'\n", match, policy)
	}
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

	match := "132dc9269812ba71ca9776ae8fa84a79f0a7dafb1b65fdb09c171e110532f3dd"

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
