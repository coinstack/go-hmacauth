package hmacauth

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// Test helpers from martini
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func refute(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("Did not expect %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

// Make getting test times easier

func secondsFromNow(seconds int32) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}

func secondsAgo(seconds int32) time.Time {
	return time.Now().Add(time.Duration(seconds*-1) * time.Second)
}

func Test_validateTimeout_invalid_future_date(t *testing.T) {
	future := secondsFromNow(60 * 16)
	err := validateTimestamp(future, &Options{})
	refute(t, err, nil)
	expect(t, err.Error(), "Timestamp out of range")
}

func Test_validateTimeout_valid_future_date(t *testing.T) {
	future := secondsFromNow(5)
	err := validateTimestamp(future, &Options{})
	expect(t, err, nil)
}

func Test_validateTimeout_now(t *testing.T) {
	now := time.Now()
	err := validateTimestamp(now, &Options{})
	expect(t, err, nil)
}

func Test_validateTimeout_past_no_timeout_set(t *testing.T) {
	past := secondsAgo(300)
	err := validateTimestamp(past, &Options{})
	expect(t, err, nil)
}

func Test_validateTimeout_expired(t *testing.T) {
	past := secondsAgo(300)
	err := validateTimestamp(past, &Options{SignatureExpiresIn: 100 * time.Second})
	refute(t, err, nil)
	expect(t, err.Error(), "Signature expired")
}

func Test_validateTimeout_past_not_expired(t *testing.T) {
	past := secondsAgo(30)
	err := validateTimestamp(past, &Options{SignatureExpiresIn: 100 * time.Second})
	expect(t, err, nil)
}

func Test_repeatedParameter(t *testing.T) {
	errString := "Repeated parameter: \"Boo\" in header string"
	err := RepeatedParameterError{"Boo"}
	refute(t, err, nil)
	expect(t, err.Error(), errString)
}

func Test_parseAuthHeader(t *testing.T) {
	timestampStr := time.Now().Format(time.RFC3339)
	timestamp, _ := time.Parse(time.RFC3339, timestampStr)
	authHeader :=
		fmt.Sprintf("APIKey=12345678,Signature=1234567890,Timestamp=%s", timestampStr)
	ab, err := parseAuthHeader(authHeader)
	expect(t, err, nil)
	refute(t, ab, nil)
	expect(t, ab.APIKey, "12345678")
	expect(t, ab.Signature, "1234567890")
	expect(t, ab.Timestamp, timestamp)
}

func Test_parseAuthHeader_invalid_timestamp(t *testing.T) {
	authHeader :=
		fmt.Sprintf("APIKey=12345678,Signature=1234567890,Timestamp=%s", "not a valid timestamp")
	_, err := parseAuthHeader(authHeader)
	refute(t, err, nil)
}

func Test_parseAuthHeader_repeated_key(t *testing.T) {
	authHeader :=
		fmt.Sprintf("APIKey=12345678,APIKey=456789,Signature=1234567890,Timestamp=%s", time.Now().Format(time.RFC3339))
	_, err := parseAuthHeader(authHeader)
	refute(t, err, nil)
}

func Test_parseAuthHeader_missing_APIKey(t *testing.T) {
	authHeader :=
		fmt.Sprintf("Signature=1234567890,Timestamp=%s", time.Now().Format(time.RFC3339))
	_, err := parseAuthHeader(authHeader)
	refute(t, err, nil)
}

func Test_parseAuthHeader_missing_Signature(t *testing.T) {
	authHeader :=
		fmt.Sprintf("APIKey=12345678,Timestamp=%s", time.Now().Format(time.RFC3339))
	_, err := parseAuthHeader(authHeader)
	refute(t, err, nil)
}

func Test_parseAuthHeader_missing_Timestamp(t *testing.T) {
	authHeader := "APIKey=12345678,Signature=1234567890"
	_, err := parseAuthHeader(authHeader)
	refute(t, err, nil)
}

func Test_stringToSign(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	timestampStr := time.Now().Format(time.RFC3339)
	options := Options{}

	str := stringToSign(req, &options, timestampStr)
	expectedStr := "GET\n" +
		"testhost.test\n" +
		"/some/path\n" +
		timestampStr + "\n"
	expect(t, expectedStr, str)
}

func Test_stringToSign_with_headers(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	req.Header.Add("X-Test1", "12345678")
	req.Header.Add("X-Test2", "87654321")

	timestampStr := time.Now().Format(time.RFC3339)
	options := Options{
		SignedHeaders: []string{"X-Test1", "X-Test2"},
	}

	str := stringToSign(req, &options, timestampStr)
	expectedStr := "GET\n" +
		"testhost.test\n" +
		"/some/path\n" +
		timestampStr + "\n" +
		"12345678\n" +
		"87654321\n"

	expect(t, expectedStr, str)
}

func Test_stringToSign_with_ordered_headers(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	req.Header.Add("B-Test", "87654321")
	req.Header.Add("A-Test", "12345678")

	timestampStr := time.Now().Format(time.RFC3339)
	options := Options{
		SignedHeaders: []string{"B-Test", "A-Test"},
	}

	str := stringToSign(req, &options, timestampStr)
	expectedStr := "GET\n" +
		"testhost.test\n" +
		"/some/path\n" +
		timestampStr + "\n" +
		"87654321\n" +
		"12345678\n"

	expect(t, expectedStr, str)
}

func Test_stringToSign_missing_required_header(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	req.Header.Add("X-Test1", "12345678")

	timestampStr := time.Now().Format(time.RFC3339)
	options := Options{
		SignedHeaders: []string{"X-Test1", "X-Test2"},
	}

	str := stringToSign(req, &options, timestampStr)
	expectedStr := "GET\n" +
		"testhost.test\n" +
		"/some/path\n" +
		timestampStr + "\n" +
		"12345678\n" +
		"\n"

	expect(t, expectedStr, str)
}

func Test_HMACAuth_invalid_options(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Should have had a panic...")
		}
	}()
	HMACAuth(Options{})
}

func Test_HMACAuth_no_auth_header(t *testing.T) {
	options := Options{
		SecretKey: func(apiKey string) (string, string) {
			return "", "secret"
		},
	}
	middlewareFunc := HMACAuth(options)

	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	w := httptest.NewRecorder()

	middlewareFunc(w, req)
	expect(t, w.Code, 401)
	expect(t, "Missing required header: \"Authorization\"\n", w.Body.String())
}

func Test_HMACAuth_bad_api_key(t *testing.T) {
	options := Options{
		SecretKey: func(apiKey string) (string, string) {
			return "", ""
		},
	}
	middlewareFunc := HMACAuth(options)

	authHeader :=
		fmt.Sprintf("APIKey=12345678,Signature=1234567890,Timestamp=%s", time.Now().Format(time.RFC3339))

	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	req.Header.Add("Authorization", authHeader)

	w := httptest.NewRecorder()

	middlewareFunc(w, req)
	expect(t, w.Code, 401)
	expect(t, "Invalid APIKey\n", w.Body.String())
}

func Test_HMACAuth_incorrect_header_order_in_string_to_sign(t *testing.T) {
	options := Options{
		SignedHeaders: []string{"A-Test", "B-Test"},
		SecretKey:     func(apiKey string) (string, string) { return "", "secret" },
	}
	middlewareFunc := HMACAuth(options)

	timestampStr := time.Now().Format(time.RFC3339)
	badStrToSign := "GET\n" +
		"testhost.test\n" +
		"/some/path\n" +
		timestampStr + "\n" +
		"12345678\n" + // Values are in reverse order here
		"87654321\n"

	sig := signString(badStrToSign, "secret")

	authHeader :=
		fmt.Sprintf("APIKey=12345678,Signature=%s,Timestamp=%s", sig, timestampStr)

	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	req.Header.Add("Authorization", authHeader)
	req.Header.Add("A-Test", "87654321")
	req.Header.Add("B-Test", "12345678")

	w := httptest.NewRecorder()

	middlewareFunc(w, req)
	expect(t, w.Code, 401)
	expect(t, "Invalid Signature\n", w.Body.String())
}

func Test_HMACAuth_bad_signature(t *testing.T) {
	options := Options{
		SecretKey: func(apiKey string) (string, string) {
			return "", "secret"
		},
	}
	middlewareFunc := HMACAuth(options)

	authHeader :=
		fmt.Sprintf("APIKey=12345678,Signature=1234567890,Timestamp=%s", time.Now().Format(time.RFC3339))

	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	req.Header.Add("Authorization", authHeader)

	w := httptest.NewRecorder()

	middlewareFunc(w, req)
	expect(t, w.Code, 401)
	expect(t, "Invalid Signature\n", w.Body.String())
}

func Test_HMACAuth(t *testing.T) {
	options := Options{
		SecretKey: func(apiKey string) (string, string) {
			return "", "secret"
		},
	}
	middlewareFunc := HMACAuth(options)

	timestampStr := time.Now().Format(time.RFC3339)
	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	strToSign := stringToSign(req, &options, timestampStr)
	_, secret := options.SecretKey("")
	sig := signString(strToSign, secret)

	authHeader :=
		fmt.Sprintf("APIKey=12345678,Signature=%s,Timestamp=%s", sig, timestampStr)
	req.Header.Add("Authorization", authHeader)

	w := httptest.NewRecorder()

	middlewareFunc(w, req)
	expect(t, w.Code, 200)
}

func Test_SignRequest(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://testhost.test/some/path?key=value&more=stuff", nil)
	req.Header.Add("B-Test", "87654321")
	req.Header.Add("A-Test", "12345678")

	apiKey := "TESTAPIKEY12345"
	secret := "TESTSECRET12345"
	timestampStr := GetTimestamp()
	options := Options{
		SignedHeaders: []string{"B-Test", "A-Test"},
		SecretKey: func(apiKey string) (string, string) {
			return "", secret
		},
	}

	SignRequest(req, apiKey, secret, &options, timestampStr)
	refute(t, req.Header.Get(authorizationHeader), "")

	// test using handler
	middlewareFunc := HMACAuth(options)
	w := httptest.NewRecorder()
	middlewareFunc(w, req)
	expect(t, w.Code, 200)
}

func Test_SignPOSTRequest(t *testing.T) {
	jsonStr := []byte(`{foo:"bar"}`)
	req, _ := http.NewRequest("POST", "http://testhost.test/some/path?key=value&more=stuff", bytes.NewBuffer(jsonStr))
	rawMD5 := md5.Sum(jsonStr)
	req.Header.Add("Content-MD5", base64.StdEncoding.EncodeToString(rawMD5[:]))
	req.Header.Add("B-Test", "87654321")
	req.Header.Add("A-Test", "12345678")

	apiKey := "TESTAPIKEY12345"
	secret := "TESTSECRET12345"
	timestampStr := GetTimestamp()
	options := Options{
		SignedHeaders: []string{"Content-MD5", "B-Test", "A-Test"},
		SecretKey: func(apiKey string) (string, string) {
			return "", secret
		},
	}

	SignRequest(req, apiKey, secret, &options, timestampStr)
	refute(t, req.Header.Get(authorizationHeader), "")

	// test using handler
	middlewareFunc := HMACAuth(options)
	w := httptest.NewRecorder()
	middlewareFunc(w, req)
	expect(t, w.Code, 200)

	// corrupt request by changing md5
	jsonStr = []byte(`{foo:"bar2"}`)
	rawMD5 = md5.Sum(jsonStr)
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(rawMD5[:]))
	// before signing -> sign does not match md5 header
	w = httptest.NewRecorder()
	middlewareFunc(w, req)
	expect(t, w.Code, 401)
	// after signing -> md5 header matches sign but not body
	w = httptest.NewRecorder()
	SignRequest(req, apiKey, secret, &options, timestampStr)
	middlewareFunc(w, req)
	expect(t, w.Code, 401)
	// setting body makes it valid again -> sign, md5, body matches
	req, _ = http.NewRequest("POST", "http://testhost.test/some/path?key=value&more=stuff", bytes.NewBuffer(jsonStr))
	rawMD5 = md5.Sum(jsonStr)
	req.Header.Add("Content-MD5", base64.StdEncoding.EncodeToString(rawMD5[:]))
	req.Header.Add("B-Test", "87654321")
	req.Header.Add("A-Test", "12345678")
	SignRequest(req, apiKey, secret, &options, timestampStr)
	w = httptest.NewRecorder()
	middlewareFunc(w, req)
	expect(t, w.Code, 200)

}
