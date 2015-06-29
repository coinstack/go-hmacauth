package hmacauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	// common parameters
	authorizationHeader = "Authorization"
	userHeader          = "User"
	apiKeyParam         = "APIKey"
	signatureParam      = "Signature"
	timestampParam      = "Timestamp"
	contentMD5          = "Content-MD5"

	// timestamp validation
	maxNegativeTimeOffset time.Duration = -15 * time.Minute

	// parsing bits
	empty   = ""
	comma   = ","
	space   = " "
	eqSign  = "="
	newline = "\n"
)

type (
	middleware func(http.ResponseWriter, *http.Request)
	KeyLocator func(string) (string, string)
)

type Options struct {
	SignedHeaders      []string
	SecretKey          KeyLocator
	SignatureExpiresIn time.Duration
}

type authBits struct {
	APIKey          string
	Signature       string
	TimestampString string
	Timestamp       time.Time
}

func (ab *authBits) IsValid() bool {
	return ab.APIKey != empty &&
		ab.Signature != empty &&
		!ab.Timestamp.IsZero()
}

func (ab *authBits) SetTimestamp(isoTime string) (err error) {
	ab.Timestamp, err = time.Parse(time.RFC3339, isoTime)
	if err == nil {
		ab.TimestampString = isoTime
	}
	return
}

func HMACAuth(options Options) middleware {
	// Validate options
	if options.SecretKey == nil {
		panic(secretKeyRequired)
	}

	return func(res http.ResponseWriter, req *http.Request) {
		var (
			err  error
			ab   *authBits
			user string
			sk   string
		)

		if ab, err = parseAuthHeader(req.Header.Get(authorizationHeader)); err == nil {
			if err = validateTimestamp(ab.Timestamp, &options); err == nil {
				var sts string
				sts = stringToSign(req, &options, ab.TimestampString)
				if user, sk = options.SecretKey(ab.APIKey); sk != empty {
					if ab.Signature == signString(sts, sk) {
						if req.Body != nil {
							// check if MD5 is present
							for _, header := range options.SignedHeaders {
								if header == contentMD5 {
									// then there should be MD5 hash for body
									bodyBytes, _ := ioutil.ReadAll(req.Body)
									bodyBytesLength := len(bodyBytes)
									if bodyBytesLength > 0 {
										if req.Header.Get(contentMD5) == "" {
											err = HMACAuthError{missingMD5}
										} else {
											// calculate MD5
											md5String := fmt.Sprintf("%x", md5.Sum(bodyBytes))
											// compare to MD5 given
											if req.Header.Get(contentMD5) != md5String {
												err = HMACAuthError{invalidMD5}
											}
										}
									}
									req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
								}
							}
						}
					} else {
						err = HMACAuthError{invalidSignature}
					}
				} else {
					err = HMACAuthError{invalidAPIKey}
				}
			}
		}

		if err != nil {
			log.Println(err.Error())
			http.Error(res, err.Error(), 401)
		}

		// set user as header
		req.Header.Add(userHeader, user)
	}
}

func GetTimestamp() string {
	return time.Now().Format(time.RFC3339)
}

func SignRequest(req *http.Request, apiKey string, secret string, options *Options, timestamp string) {
	sts := stringToSign(req, options, timestamp)
	signature := signString(sts, secret)
	authHeader := fmt.Sprintf("APIKey=%s,Signature=%s,Timestamp=%s", apiKey, signature, timestamp)
	req.Header.Set(authorizationHeader, authHeader)
}

func signString(str string, secret string) string {
	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func stringToSign(req *http.Request, options *Options, timestamp string) string {
	var buffer bytes.Buffer

	// Standard
	buffer.WriteString(req.Method)
	buffer.WriteString(newline)
	buffer.WriteString(req.Host)
	buffer.WriteString(newline)
	buffer.WriteString(req.URL.RequestURI())
	buffer.WriteString(newline)
	buffer.WriteString(timestamp)
	buffer.WriteString(newline)

	// Headers
	for _, header := range options.SignedHeaders {
		val := req.Header.Get(header)
		if val == empty {
			buffer.WriteString(newline)
		} else {
			buffer.WriteString(val)
			buffer.WriteString(newline)
		}
	}

	return buffer.String()
}

func parseAuthHeader(header string) (*authBits, error) {
	if header == empty {
		return nil, HeaderMissingError{authorizationHeader}
	}

	ab := new(authBits)
	parts := strings.Split(header, comma)
	for _, part := range parts {
		kv := strings.SplitN(strings.Trim(part, space), eqSign, 2)
		if kv[0] == apiKeyParam {
			if ab.APIKey != empty {
				return nil, RepeatedParameterError{kv[0]}
			}
			ab.APIKey = kv[1]
		} else if kv[0] == signatureParam {
			if ab.Signature != empty {
				return nil, RepeatedParameterError{kv[0]}
			}
			ab.Signature = kv[1]
		} else if kv[0] == timestampParam {
			if !ab.Timestamp.IsZero() {
				return nil, RepeatedParameterError{kv[0]}
			}
			if ab.SetTimestamp(kv[1]) != nil {
				return nil, HMACAuthError{invalidTimestamp}
			}
		} else {
			return nil, HMACAuthError{invalidParameter}
		}
	}

	if !ab.IsValid() {
		return nil, HMACAuthError{missingParameter}
	}

	return ab, nil
}

func validateTimestamp(ts time.Time, options *Options) error {
	reqAge := time.Since(ts)

	// Allow for about `maxNegativeTimeOffset` of difference, some servers are
	// ahead and some are behind
	if reqAge < maxNegativeTimeOffset {
		return HMACAuthError{tsOutOfRange}
	}

	if options.SignatureExpiresIn != 0 {
		if reqAge > options.SignatureExpiresIn {
			return HMACAuthError{signatureExpired}
		}
	}

	return nil
}
