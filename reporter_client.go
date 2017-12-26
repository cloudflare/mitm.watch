// Requests test cases from the server (server will prepare too for test),
// executes test cases and let the server mark the test as finished. (Once
// finished, the server can perform additional MITM detection on the results.)

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// convenience type for building JSON
type H map[string]interface{}

var httpClient = &http.Client{}

// doRequest performs a request to the given path with the given request body
// (serialized as JSON). The response body is deserialized to respBody on
// success. (Either bodies can be nil in case no body is expected.) Otherwise
// the error reason is returned.
func doRequest(method, path string, reqBody interface{}, respBody interface{}) error {
	var requestBody io.Reader
	if reqBody != nil {
		json, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to prepare request body: %s", err)
		}
		requestBody = bytes.NewBuffer(json)
	}
	req, err := http.NewRequest(method, apiPrefix+path, requestBody)
	if err != nil {
		return err
	}
	req.Header.Set("X-Requested-With", "net/http")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed request: %s", err)
	}
	defer resp.Body.Close()

	var bodyBytes []byte
	if resp.Body != nil {
		if bodyBytes, err = ioutil.ReadAll(resp.Body); err != nil {
			return fmt.Errorf("failed to read body: %s", err)
		}
	}

	// handle API errors
	if resp.StatusCode/100 != 2 {
		var errObj errorResponse
		if bodyBytes != nil {
			json.Unmarshal(bodyBytes, &errObj)
		}
		if len(errObj.Error) != 0 {
			return fmt.Errorf("request failed: %s", errObj.Error)
		}
		return fmt.Errorf("Request failed with error code %d %s", resp.StatusCode, resp.Status)
	}

	if respBody != nil {
		// try to deserialize the response body.
		if bodyBytes == nil {
			return fmt.Errorf("Missing response body, status code was %d %s", resp.StatusCode, resp.Status)
		}
		if err = json.Unmarshal(bodyBytes, respBody); err != nil {
			return fmt.Errorf("failed to parse response: %s", err)
		}
	}

	return nil
}

// CreateTest starts a test and obtains the test cases.
func CreateTest(testRequest createTestRequest, anonymous bool) (string, []SubtestSpec, error) {
	var testResponse createTestResponse
	url := "/tests"
	if anonymous {
		url += "?anonymous"
	}
	err := doRequest("POST", url, testRequest, &testResponse)
	if err != nil {
		return "", nil, err
	}
	if testResponse.TestID == "" {
		return "", nil, errors.New("Missing Test ID")
	}
	return testResponse.TestID, testResponse.Subtests, nil
}

// SaveTestResult saves the results of one test case, it must be executed only
// once for the given subtest within a test.
func SaveTestResult(testId string, subtestNumber int, testResult clientResult) error {
	endpoint := fmt.Sprintf("/tests/%s/subtests/%d/clientresult",
		testId, subtestNumber)
	return doRequest("PUT", endpoint, testResult, nil)
}
