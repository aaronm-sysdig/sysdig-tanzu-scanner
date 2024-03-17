package sysdighttp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type SysdigRequestConfig struct {
	Method     string
	URL        string
	Headers    map[string]string
	Params     map[string]interface{}
	JSON       interface{}
	Data       map[string]string
	Auth       [2]string
	Verify     bool
	Stream     bool
	MaxRetries int
	BaseDelay  int
	MaxDelay   int
	Timeout    int
}

func DefaultSysdigRequestConfig() SysdigRequestConfig {
	return SysdigRequestConfig{
		Method:     "GET",
		Verify:     false,
		MaxRetries: 1,
		BaseDelay:  5,
		MaxDelay:   60,
		Timeout:    600,
	}
}

//goland:noinspection GoBoolExpressions
func SysdigRequest(SysdigRequest SysdigRequestConfig) (*http.Response, error) {
	retries := 0
	// Initialize the request body as an io.Reader
	var requestBody io.Reader

	var resp *http.Response

	for retries <= SysdigRequest.MaxRetries {
		// Check the Content-Type to determine how to encode the request body
		if contentType, ok := SysdigRequest.Headers["Content-Type"]; ok && contentType == "application/x-www-form-urlencoded" {
			// Encode the Data map as URL-encoded form data
			data := url.Values{}
			for key, value := range SysdigRequest.Data {
				data.Set(key, value)
			}
			requestBody = strings.NewReader(data.Encode())
		} else if SysdigRequest.JSON != nil {
			// Handle JSON data as before
			byteData, err := json.Marshal(SysdigRequest.JSON)
			if err != nil {
				return nil, fmt.Errorf("SysdigRequest:: failed to marshal JSON data: %w", err)
			}
			requestBody = bytes.NewBuffer(byteData)
		}

		u, err := url.Parse(SysdigRequest.URL)
		if err != nil {
			return nil, fmt.Errorf("SysdigRequest:: failed to parse URL: %w", err)
		}

		params := url.Values{}
		for k, v := range SysdigRequest.Params {
			switch value := v.(type) {
			case int:
				params.Add(k, strconv.Itoa(value))
			case string:
				params.Add(k, value)
			default:
				// Handle unexpected types if necessary, or ignore them
			}
		}
		u.RawQuery = params.Encode()

		req, err := http.NewRequest(SysdigRequest.Method, SysdigRequest.URL, requestBody)
		if err != nil {
			return nil, fmt.Errorf("SysdigRequest:: failed to create request: %w", err)
		}

		for k, v := range SysdigRequest.Headers {
			req.Header.Set(k, v)
		}

		if len(SysdigRequest.Auth) == 2 {
			if SysdigRequest.Auth[0] != "" {
				req.SetBasicAuth(SysdigRequest.Auth[0], SysdigRequest.Auth[1])
			}
		}

		// Create custom Transport that allows us to control TLSClientConfig
		customTransport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !SysdigRequest.Verify, // Notice the negation here, because InsecureSkipVerify is true when we want to skip verification
			},
		}

		// Use the custom Transport with the http.Client
		client := &http.Client{
			Timeout:   time.Duration(SysdigRequest.Timeout) * time.Second,
			Transport: customTransport, // Set the custom transport
		}

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if err == nil {
			// log status code if request did not fail
			log.Printf("SysdigRequest:: Received HTTP status code: %d", resp.StatusCode)
			respBody, _ := io.ReadAll(resp.Body)
			log.Printf("SysdigRequest:: Response body: %s", string(respBody))
			resp.Body.Close() // ensure response body is closed
		}

		log.Printf("SysdigRequest:: Error: %v. Retrying in %d seconds...", err, SysdigRequest.BaseDelay)
		log.Printf("SysdigRequest:: StatusCode: '%d', Retry: %d/%d, Sleeping for %d seconds", resp.StatusCode, retries, SysdigRequest.MaxRetries, SysdigRequest.BaseDelay)
		time.Sleep(time.Duration(SysdigRequest.BaseDelay) * time.Second)
		retries++
	}

	log.Printf("SysdigRequest:: Failed to fetch data from %s after %d retries.", SysdigRequest.URL, SysdigRequest.MaxRetries)
	log.Printf("SysdigRequest:: Error making request to %s", SysdigRequest.URL)

	// Manually create an HTTP response with a 503 status code
	resp = &http.Response{
		Status:     "503 Service Unavailable",
		StatusCode: http.StatusServiceUnavailable,
		Body:       io.NopCloser(bytes.NewBufferString("Service is unavailable after retries.")),
	}
	return resp, fmt.Errorf("SysdigRequest:: error %s, failed after %d retries", "503", SysdigRequest.MaxRetries)
}

func ResponseBodyToJson(resp *http.Response, target interface{}) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	err = json.Unmarshal(body, target)
	if err != nil {
		return err
	}

	return nil
}
