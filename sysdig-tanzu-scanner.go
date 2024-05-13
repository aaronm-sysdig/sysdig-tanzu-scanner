package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/text/message"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"sysdig-tanzu-scanner/sysdighttp"
	"sysdig-tanzu-scanner/types/config"
	"sysdig-tanzu-scanner/types/currentdroplet"
	"sysdig-tanzu-scanner/types/deployedrevision"
	"sysdig-tanzu-scanner/types/executionresults"
	"sysdig-tanzu-scanner/types/oauthtoken"
	"sysdig-tanzu-scanner/types/oci"
	"sysdig-tanzu-scanner/types/organizationpayload"
	ResultsJSON "sysdig-tanzu-scanner/types/results"
	"sysdig-tanzu-scanner/types/results-old"
	"sysdig-tanzu-scanner/types/runningapps"
	"sysdig-tanzu-scanner/types/spacepayload"
	"time"
)

func parseConfigFile() (config.Config, error) {
	var err error
	log.Debug("parseConfigFile:: Enter()")

	tanzuConfig := config.Config{}

	var data []byte
	if data, err = os.ReadFile("config.yaml"); err != nil {
		return config.Config{}, fmt.Errorf("error reading config file: %v", err)
	}

	if err = yaml.Unmarshal(data, &tanzuConfig); err != nil {
		return config.Config{}, fmt.Errorf("error parsing config file: %v", err)
	}

	if tanzuConfig.Settings.LogLevel == "" ||
		tanzuConfig.Config.CFAuthEndpoint == "" ||
		tanzuConfig.Config.CFAPIEndpoint == "" ||
		len(tanzuConfig.Stacks) == 0 {
		return config.Config{}, errors.New("config validation failed: missing required fields")
	}

	log.Debug("parseConfigFile:: Exit()")
	return tanzuConfig, nil
}

func decodeConfigCredentials(yamlConfig *config.Config) {
	var err error
	log.Info("decodeConfigCredentials:: Enter()")

	if yamlConfig.Config.CFClientID == "" {
		log.Info("decodeConfigCredentials:: CFClientID is empty, using Username/Password")
		// Decode the base64 encoded username
		var decodedUsername []byte
		if decodedUsername, err = base64.StdEncoding.DecodeString(yamlConfig.Config.CFUsername); err != nil {
			log.Fatalf("decodeConfigCredentials:: Could not decode CFUsername. Error: %v", err)
		}

		// Decode the base64 encoded password
		var decodedPassword []byte
		if decodedPassword, err = base64.StdEncoding.DecodeString(yamlConfig.Config.CFPassword); err != nil {
			log.Fatalf("decodeConfigCredentials:: Could not decode CFPassword. Error: %v", err)
		}

		yamlConfig.Config.CFUsername = string(decodedUsername)
		yamlConfig.Config.CFPassword = string(decodedPassword)
	} else {
		log.Info("decodeConfigCredentials:: CFClientID != '', skipping Username/Password decoding")

	}

	log.Info("decodeConfigCredentials:: Exit()")
}

/*func refreshAccesstoken(config *Config, existingOAuthToken *OAuthToken, creds *Credentials) (*OAuthToken, error) {
	if !existingOAuthToken.IsValid() {
		newOAuthToken, _ := getAccessToken(config, creds)
		return newOAuthToken, nil
	} else {
		return existingOAuthToken, nil
	}
}*/

func _log(workerResult *executionresults.WorkerResult, msg string) {
	if workerResult == nil {
		log.Print(msg)
	} else {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprint(msg))
	}
}

func getAccessTokenClientCredentials(yamlConfig *config.Config, workerResult *executionresults.WorkerResult) (oAuthToken *oauthtoken.OAuthToken, err error) {
	_log(workerResult, "getAccessTokenClientCredentials:: Enter()")

	configLogin := sysdighttp.DefaultSysdigRequestConfig()
	configLogin.Method = "POST"
	configLogin.URL = yamlConfig.Config.CFAuthEndpoint
	configLogin.Verify = false
	configLogin.Headers = map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	configLogin.Data = map[string]string{
		"client_id":     yamlConfig.Config.CFClientID,
		"client_secret": yamlConfig.Config.CFClientSecret,
		"grant_type":    yamlConfig.Config.CFClientGrantType,
		"scope":         yamlConfig.Config.CFClientScope,
		"token_format":  yamlConfig.Config.CFTokenFormat,
	}

	var objResponse *http.Response
	_log(workerResult, fmt.Sprintf("getAccessTokenClientCredentials:: Executing URL: %s", configLogin.URL))

	if objResponse, err = sysdighttp.SysdigRequest(configLogin); err != nil {
		log.Fatalf("getAccessTokenClientCredentials:: Failed to execute query to get token. Error: %v", err)
	}

	// Initialize oAuthToken before unmarshalling the JSON into it, so we have a valid construct to use
	oAuthToken = &oauthtoken.OAuthToken{}

	if err = sysdighttp.ResponseBodyToJson(objResponse, oAuthToken); err != nil {
		log.Fatalf("getAccessTokenClientCredentials:: ResponseBodyToJson error: %v", err)
	}
	defer objResponse.Body.Close()

	// Calculate the expiry time based on the current time and expires_in value
	oAuthToken.ExpiryTime = time.Now().Add(time.Second * time.Duration(oAuthToken.ExpiresIn))

	_log(workerResult, fmt.Sprintf("getAccessTokenClientCredentials:: Exit()"))

	return oAuthToken, nil
}

func getAccessTokenPassword(yamlConfig *config.Config, workerResult *executionresults.WorkerResult) (oAuthToken *oauthtoken.OAuthToken, err error) {
	_log(workerResult, fmt.Sprint("getAccessTokenPassword:: Enter()"))

	configLogin := sysdighttp.DefaultSysdigRequestConfig()
	configLogin.Method = "POST"
	configLogin.URL = yamlConfig.Config.CFAuthEndpoint
	configLogin.Verify = false
	configLogin.Auth = [2]string{"cf", ""}
	configLogin.Headers = map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	configLogin.Data = map[string]string{
		"username":   yamlConfig.Config.CFUsername,
		"password":   yamlConfig.Config.CFPassword,
		"grant_type": "password",
	}

	var objResponse *http.Response
	_log(workerResult, fmt.Sprintf("getAccessTokenPassword:: Executing URL: %s", configLogin.URL))

	if objResponse, err = sysdighttp.SysdigRequest(configLogin); err != nil {
		log.Fatalf("getAccessTokenPassword:: Failed to execute query to get token. Error: %v", err)
	}

	// Initialize oAuthToken before unmarshalling the JSON into it, so we have a valid construct to use
	oAuthToken = &oauthtoken.OAuthToken{}

	if err = sysdighttp.ResponseBodyToJson(objResponse, oAuthToken); err != nil {
		log.Fatalf("getAccessTokenPassword:: ResponseBodyToJson error: %v", err)
	}
	defer objResponse.Body.Close()

	// Calculate the expiry time based on the current time and expires_in value
	oAuthToken.ExpiryTime = time.Now().Add(time.Second * time.Duration(oAuthToken.ExpiresIn))

	_log(workerResult, fmt.Sprint("getAccessTokenPassword:: Exit()"))

	return oAuthToken, nil
}

func getAccessToken(yamlConfig *config.Config, workerResult *executionresults.WorkerResult) (oAuthToken *oauthtoken.OAuthToken, err error) {
	_log(workerResult, fmt.Sprint("getAccessToken:: Enter()"))

	if yamlConfig.Config.CFClientID != "" {
		oAuthToken, err = getAccessTokenClientCredentials(yamlConfig, workerResult)
	} else if yamlConfig.Config.CFUsername != "" {
		oAuthToken, err = getAccessTokenPassword(yamlConfig, workerResult)
	}

	_log(workerResult, fmt.Sprint("getAccessToken:: Exit()"))

	return oAuthToken, err
}

func generateRunningApps(yamlConfig *config.Config, authToken *oauthtoken.OAuthToken) ([]runningapps.Resource, error) {
	log.Info("generateRunningApps:: Enter()")
	var err error

	if !authToken.IsValid() {
		if authToken, err = getAccessToken(yamlConfig, nil); err != nil {
			log.Fatalf("generateRunningApps:: Failed to refresh OAuthToken. Error: %v", err)
		}
	}

	configOrgApps := sysdighttp.DefaultSysdigRequestConfig()
	configOrgApps.URL = fmt.Sprintf("%s/v3/apps?lifecycle_type=buildpack&per_page=5000", yamlConfig.Config.CFAPIEndpoint)
	configOrgApps.Headers = map[string]string{
		"authorization": "bearer " + authToken.AccessToken,
	}

	log.Printf("generateRunningApps:: Executing URL: %s", configOrgApps.URL)
	var objResponse *http.Response
	if objResponse, err = sysdighttp.SysdigRequest(configOrgApps); err != nil {
		return nil, fmt.Errorf("generateRunningApps:: Failed to get running apps. Error: %s", err)
	}

	var jsonRunningAppsComplete runningapps.RunningApps
	if err = sysdighttp.ResponseBodyToJson(objResponse, &jsonRunningAppsComplete); err != nil {
		return nil, fmt.Errorf("generateRunningApps:: ResponseBodyToJson error: %v", err)
	}
	for _, app := range jsonRunningAppsComplete.Resources {
		log.Printf("generateRunningApps:: Adding app to process. App: '%s', Buildpack: '%s', Stack: '%s'", app.Name, app.Lifecycle.Data.Buildpacks, app.Lifecycle.Data.Stack)
	}
	log.Info("generateRunningApps:: Exit()")
	return jsonRunningAppsComplete.Resources, nil
}

func getSpace(appName string, spaceURL string, oAuthToken *oauthtoken.OAuthToken, workerResult *executionresults.WorkerResult) (jsonSpace *spacepayload.SpacePayload, err error) {
	workerResult.Logs = append(workerResult.Logs, "getSpace:: Enter()")

	configSpace := sysdighttp.DefaultSysdigRequestConfig()
	configSpace.URL = spaceURL
	configSpace.Method = "GET"
	configSpace.Verify = false
	configSpace.Headers = map[string]string{
		"authorization": "bearer " + oAuthToken.AccessToken,
	}

	_log(workerResult, fmt.Sprintf("getSpaceName:: Executing URL: %s", configSpace.URL))
	var objSpaceResponse *http.Response
	if objSpaceResponse, err = sysdighttp.SysdigRequest(configSpace); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getSpaceName:: Failed to execute query to get space for %v.  Error: %v", appName, err))
		workerResult.ResultReason = "Failed to execute query to get space"
		return nil, err
	}

	if err = sysdighttp.ResponseBodyToJson(objSpaceResponse, &jsonSpace); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getSpaceName:: Failed to get space for %v.  Error: %v", appName, err))
		workerResult.ResultReason = "Failed to get space after querying for space URL"
		return nil, err
	}
	workerResult.RunningApp.Space = *jsonSpace

	if len(jsonSpace.Name) == 0 {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getSpaceName:: space length is 0 for %v", appName))
		workerResult.ResultReason = "Space length is 0"
		return nil, err
	}

	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getSpace:: Exit()"))

	return jsonSpace, nil
}

func getDeployedRevision(appName string, deployedRevisionURL string, oAuthToken *oauthtoken.OAuthToken, workerResult *executionresults.WorkerResult) (intDeployedRevisionVersion int64, err error) {
	workerResult.Logs = append(workerResult.Logs, "getDeployedRevision:: Enter()")

	configDeployedRevision := sysdighttp.DefaultSysdigRequestConfig()
	configDeployedRevision.URL = deployedRevisionURL
	configDeployedRevision.Method = "GET"
	configDeployedRevision.Verify = false
	configDeployedRevision.Headers = map[string]string{
		"authorization": "bearer " + oAuthToken.AccessToken,
	}
	_log(workerResult, fmt.Sprintf("getDeployedRevision:: Executing URL: %s", configDeployedRevision.URL))

	var objDeployedRevisionResponse *http.Response
	if objDeployedRevisionResponse, err = sysdighttp.SysdigRequest(configDeployedRevision); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getDeployedRevision:: Failed to exequte query to get deployed revision for %v.  Error: %v", appName, err))
		workerResult.ResultReason = " Failed to exequte query to get deployed revision, defaulting to 0 and continuing"
		workerResult.DeployedRevisionVersion = 0
		return 0, err
	}
	var jsonDeployedRevision deployedrevision.DeployedRevisionsResponse
	err = sysdighttp.ResponseBodyToJson(objDeployedRevisionResponse, &jsonDeployedRevision)

	// Get the version of set it to 0
	if len(jsonDeployedRevision.Resources) >= 1 {
		workerResult.DeployedRevisionVersion = jsonDeployedRevision.Resources[0].Version
	} else {
		workerResult.DeployedRevisionVersion = 0
	}

	workerResult.Logs = append(workerResult.Logs, "getDeployedRevision:: Exit()")
	return workerResult.DeployedRevisionVersion, nil
}

func getOrganization(appName string, organizationURL string, oAuthToken *oauthtoken.OAuthToken, workerResult *executionresults.WorkerResult) (jsonOrganization *organizationpayload.OrganizationPayload, err error) {
	workerResult.Logs = append(workerResult.Logs, "getOrganization:: Enter()")

	configOrganization := sysdighttp.DefaultSysdigRequestConfig()
	configOrganization.URL = organizationURL
	configOrganization.Method = "GET"
	configOrganization.Verify = false
	configOrganization.Headers = map[string]string{
		"authorization": "bearer " + oAuthToken.AccessToken,
	}
	_log(workerResult, fmt.Sprintf("getOrganization:: Executing URL: %s", configOrganization.URL))

	var objOrganizationResponse *http.Response
	if objOrganizationResponse, err = sysdighttp.SysdigRequest(configOrganization); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getOrganization:: Failed to exequte query to get organization for %v.  Error: %v", appName, err))
		workerResult.ResultReason = "Failed to exequte query to get organization"
		return nil, err
	}

	if err = sysdighttp.ResponseBodyToJson(objOrganizationResponse, &jsonOrganization); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getOrganization:: Failed to get organization for %v.  Error: %v", appName, err))
		workerResult.ResultReason = "Failed to get organization"
		return nil, err
	}
	workerResult.RunningApp.Organization = *jsonOrganization

	if len(jsonOrganization.Name) == 0 {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getOrganization:: Organization length is 0 for %v", appName))
		workerResult.ResultReason = "Organization length is 0"
		return nil, err
	}

	workerResult.Logs = append(workerResult.Logs, "getOrganization:: Exit()")
	return jsonOrganization, nil
}

func downloadDroplet(app runningapps.Resource, dropletFilePath string, authToken *oauthtoken.OAuthToken, workerResult *executionresults.WorkerResult) error {
	var err error
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Enter()"))
	// Create the directory for the droplet file if it doesn't exist
	dir := filepath.Dir(dropletFilePath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to create directory: %v", err))
	}

	// Initial request to get the droplet download URL
	configCurrentDroplet := sysdighttp.DefaultSysdigRequestConfig()
	configCurrentDroplet.URL = app.Links["current_droplet"].Href
	configCurrentDroplet.Method = "GET"
	configCurrentDroplet.Headers = map[string]string{
		"authorization": "bearer " + authToken.AccessToken,
	}
	configCurrentDroplet.Verify = false

	_log(workerResult, fmt.Sprintf("downloadDroplet:: Executing URL: %s", configCurrentDroplet.URL))

	var objCurrentDropletResponse *http.Response
	if objCurrentDropletResponse, err = sysdighttp.SysdigRequest(configCurrentDroplet); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to get droplet info: %v", err))
		workerResult.ResultReason = "Failed to get droplet info"
		return err
	}
	defer objCurrentDropletResponse.Body.Close()

	var jsonCurrentDroplet currentdroplet.CurrentDroplet
	if err = sysdighttp.ResponseBodyToJson(objCurrentDropletResponse, &jsonCurrentDroplet); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to get download droplet link for %s", app.Name))
		workerResult.ResultReason = "Failed to get download droplet link"
		return err
	}

	// Download the droplet
	configDownload := sysdighttp.DefaultSysdigRequestConfig()
	configDownload.Method = "GET"
	configDownload.URL = jsonCurrentDroplet.Links["download"].Href
	configDownload.Verify = false
	configDownload.Headers = map[string]string{
		"authorization": "bearer " + authToken.AccessToken,
	}
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Downloading droplet for app: %s from:  %s", app.Name, jsonCurrentDroplet.Links["download"].Href))
	_log(workerResult, fmt.Sprintf("downloadDroplet:: Executing URL: %s", configDownload.URL))

	objDownloadDroplet, err := sysdighttp.SysdigRequest(configDownload)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to download droplet for app: %s. Error: : %v", app.Name, err))
		workerResult.ResultReason = "Failed to download droplet"
		return err
	}
	defer objDownloadDroplet.Body.Close()

	// Create the droplet file
	var dropletFile *os.File
	if dropletFile, err = os.Create(dropletFilePath); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to create droplet file: %v", err))
		workerResult.ResultReason = "Failed to create droplet file"
		return err

	}
	defer func(dropletFile *os.File) {
		if err := dropletFile.Close(); err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to close droplet file handler. ERROR: %v", err))
			workerResult.ResultReason = "Failed to close droplet file handler"
		}
	}(dropletFile)

	// Write the response body to file
	workerResult.Logs = append(workerResult.Logs, "downloadDroplet:: Starting to download droplet")
	var bytesCopied int64
	if bytesCopied, err = io.Copy(dropletFile, objDownloadDroplet.Body); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("Failed to write droplet to file: %v", err))
		workerResult.ResultReason = "Failed to write droplet to file"
		return err
	}
	workerResult.Logs = append(workerResult.Logs, "downloadDroplet:: Droplet download complete")
	p := message.NewPrinter(message.MatchLanguage("en"))
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Number of bytes written to file: %s", p.Sprintf("%d", bytesCopied)))
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Exit()"))
	return nil
}

func calculateSHA256(filePath string, workerResult *executionresults.WorkerResult) (string, error) {
	var file *os.File
	var err error
	if file, err = os.Open(filePath); err != nil {
		return "", err
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("calculateSHA256:: Failed to close file. ERROR: %v", err))
		}
	}(file)

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func copyFile(src, dst string, workerResult *executionresults.WorkerResult) error {
	// Open the source file for reading.
	var in *os.File
	var err error
	if in, err = os.Open(src); err != nil {
		return err
	}
	defer func(in *os.File) {
		if err := in.Close(); err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("copyFile:: Unable to close source file. ERROR: %v", err))
		}
	}(in)

	// Create the destination file for writing. Create will truncate it if it already exists.
	var out *os.File
	if out, err = os.Create(dst); err != nil {
		return err
	}
	defer func(out *os.File) {
		if err := out.Close(); err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("copyFile:: Unable to close destination file. ERROR: %v", err))
		}
	}(out)

	// Copy the contents of the source file to the destination file.
	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync() // Flush file system buffers to ensure the copy is written to disk.
}

func writeJSONToFile(filePath string, data interface{}, workerResult *executionresults.WorkerResult) error {
	var file *os.File
	var err error
	if file, err = os.Create(filePath); err != nil {
		return err

	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("writeJSONToFile:: Unable to close destination file. ERROR: %v", err))
		}
	}(file)

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ") // Pretty print JSON
	return encoder.Encode(data)
}

// calculateSHA256FromBytes takes a byte slice and returns its SHA-256 hash as a hexadecimal string.
func calculateSHA256FromBytes(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)                         // Directly hash the data
	return hex.EncodeToString(hasher.Sum(nil)) // Convert the hash to a hexadecimal string
}

// Helper function to calculate SHA-256 checksum for JSON data
func calculateSHA256ForJSON(data interface{}) (string, error) {
	var jsonBytes []byte
	var err error
	if jsonBytes, err = json.Marshal(data); err != nil {
		return "", err
	}

	hasher := sha256.New()
	hasher.Write(jsonBytes)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func logDirectoryTree(startPath string, workerResult *executionresults.WorkerResult) error {
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("logDirectoryTree:: Enter()"))
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("Directory tree of %s:", startPath))

	// filepath.Walk walks the file tree rooted at root, calling walkFn for each file or directory in the tree, including root.
	err := filepath.Walk(startPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			workerResult.Logs = append(workerResult.Logs, "logDirectoryTree:: Can't walk tree")
			return err // Return error to stop the walk
		}

		// Calculate the indentation level based on the depth of the current path from the start path
		var relativePath string
		if relativePath, err = filepath.Rel(startPath, path); err != nil {
			return err // Return error to stop the walk
		}
		level := strings.Count(relativePath, string(os.PathSeparator))
		indent := strings.Repeat("    ", level)

		if info.IsDir() {
			// For directories, append a slash to indicate that it's a directory
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("%s%s/", indent, info.Name()))
		} else {
			// For files, just print the file name
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("%s%s", indent, info.Name()))
		}

		return nil
	})

	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("Error walking through %s: %v\n", startPath, err))
	}
	workerResult.Logs = append(workerResult.Logs, "logDirectoryTree:: Exit()")
	return err
}

func buildOCIDirectory(yamlConfig *config.Config, appResource runningapps.Resource, spaceResource *spacepayload.SpacePayload, organizationResource *organizationpayload.OrganizationPayload, stackFilePath string, dropletFilePath string, workerResult *executionresults.WorkerResult) error {
	var err error

	workerResult.Logs = append(workerResult.Logs, "buildOCIDirectory:: Enter()")
	ociPath := fmt.Sprintf("%s/oci/%s/%s/%s/%s", yamlConfig.Settings.WorkingDirectory, organizationResource.Name, spaceResource.Name, appResource.GUID, appResource.Name)
	workerResult.OCIPath = ociPath
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: App: %s, OCI Path: '%s'", appResource.Name, ociPath))

	if err := os.MkdirAll(filepath.Join(ociPath, "blobs/sha256"), os.ModePerm); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to create OCI directory structure: %v", err))
		return err
	}

	ociStackFilePath := filepath.Join(ociPath, "blobs/sha256", filepath.Base(stackFilePath))
	ociDropletFilePath := filepath.Join(ociPath, "blobs/sha256", filepath.Base(dropletFilePath))

	// Copy stack and droplet files to the OCI directory if they don't already exist
	if _, err := os.Stat(ociStackFilePath); os.IsNotExist(err) {
		if err := copyFile(stackFilePath, ociStackFilePath, workerResult); err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to copy stack file: %v", err))
			return err
		}
	}
	if _, err := os.Stat(ociDropletFilePath); os.IsNotExist(err) {
		if err := copyFile(dropletFilePath, ociDropletFilePath, workerResult); err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to copy droplet file: %v", err))
			return err
		}
	}

	// Calculate SHA256 hashes for both files
	var stackSHA256 string
	if stackSHA256, err = calculateSHA256(stackFilePath, workerResult); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to calculate SHA256 for stack file: %v", err))
		return err
	}
	var stackFileInfo os.FileInfo
	if stackFileInfo, err = os.Stat(stackFilePath); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Error getting file information: %v", err))
		return err
	}

	var dropletSHA256 string
	if dropletSHA256, err = calculateSHA256(dropletFilePath, workerResult); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to calculate SHA256 for droplet file: %v", err))
		return err
	}
	workerResult.DropletSHA256Hash = fmt.Sprintf("sha256:%s", dropletSHA256)
	var dropletFileInfo os.FileInfo
	if dropletFileInfo, err = os.Stat(dropletFilePath); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Error getting file information: %v", err))
		return err
	}

	// Rename the copied files to their hash values
	newStackFilePath := filepath.Join(filepath.Dir(ociStackFilePath), stackSHA256)
	if err := os.Rename(ociStackFilePath, newStackFilePath); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to rename stack file: %v", err))
		return err
	}
	newDropletFilePath := filepath.Join(filepath.Dir(ociDropletFilePath), dropletSHA256)
	if err := os.Rename(ociDropletFilePath, newDropletFilePath); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to rename droplet file: %v", err))
		return err
	}

	// Further operations to create OCI config, manifest, and index files...
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: OCI directory structure created successfully."))

	configJSONData := oci.OCIConfigJSON{
		Created:      time.Now().Format(time.RFC3339Nano),
		Architecture: "amd64",
		OS:           "linux",
	}
	configJSONData.Config.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	configJSONData.Config.Cmd = []string{"/bin/sh"}
	configJSONData.Rootfs.Type = "layers"
	configJSONData.Rootfs.DiffIds = []string{fmt.Sprintf("sha256:%s", stackSHA256), fmt.Sprintf("sha256:%s", dropletSHA256)}

	var configBytes []byte
	if configBytes, err = json.MarshalIndent(configJSONData, "", "  "); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Error marshaling config.json: %v", err))
		return err
	}
	configSHA256 := calculateSHA256FromBytes(configBytes)
	configFilePath := filepath.Join(ociPath, "blobs", "sha256", configSHA256)
	if err := os.WriteFile(configFilePath, configBytes, 0644); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Error writing config.json: %v", err))
		return err
	}

	var configFileInfo os.FileInfo
	if configFileInfo, err = os.Stat(configFilePath); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Could not get file info for config.json at path: : %s.  Error: %v", configFilePath, err))
		return err
	}

	manifestJSONData := oci.ManifestJSON{
		SchemaVersion: 2,
		Config: struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		}{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    fmt.Sprintf("sha256:%s", configSHA256),
			Size:      configFileInfo.Size(),
		},
		Layers: []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		}{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:    fmt.Sprintf("sha256:%s", stackSHA256),
				Size:      stackFileInfo.Size(),
			},
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:    fmt.Sprintf("sha256:%s", dropletSHA256),
				Size:      dropletFileInfo.Size(),
			},
		},
	}

	var manifestSha256 string
	if manifestSha256, err = calculateSHA256ForJSON(manifestJSONData); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to calculate SHA256 for manifest JSON: %v", err))
	}

	manifestJSONPath := filepath.Join(ociPath, "blobs/sha256", manifestSha256)
	if err := writeJSONToFile(manifestJSONPath, manifestJSONData, workerResult); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to write manifest.json: %v", err))
	}

	var manifestFileInfo os.FileInfo
	if manifestFileInfo, err = os.Stat(manifestJSONPath); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Could not get file info for manifest.json at path: : %s.  Error: %v", manifestJSONPath, err))
	}

	indexJSONData := oci.IndexJSON{
		SchemaVersion: 2,
		Manifests: []struct {
			MediaType   string `json:"mediaType"`
			Digest      string `json:"digest"`
			Size        int64  `json:"size"`
			Annotations struct {
				OrgOpencontainersImageRefName string `json:"org.opencontainers.image.ref.name"`
			} `json:"annotations"`
		}{
			{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Digest:    fmt.Sprintf("sha256:%s", manifestSha256),
				Size:      manifestFileInfo.Size(),
				Annotations: struct {
					OrgOpencontainersImageRefName string `json:"org.opencontainers.image.ref.name"`
				}{
					OrgOpencontainersImageRefName: fmt.Sprintf("%s/%s/%s", organizationResource.Name, spaceResource.Name, appResource.Name),
				},
			},
		},
	}

	indexJSONPath := filepath.Join(ociPath, "index.json")
	if err := writeJSONToFile(indexJSONPath, indexJSONData, workerResult); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to write index.json: %v", err))
	}

	ociLayout := map[string]string{
		"imageLayoutVersion": "1.0.0",
	}

	ociLayoutFilePath := filepath.Join(ociPath, "oci-layout")
	var file *os.File
	if file, err = os.Create(ociLayoutFilePath); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to create oci-layout file: %v", err))
		return err
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to close oci-layout file: %v", err))
		}
	}(file)

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(ociLayout); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to write oci-layout JSON: %v", err))
	}

	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Writing oci-layout to: %s", ociLayoutFilePath))
	if err = logDirectoryTree(ociPath, workerResult); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("logDirectoryTree:: Error: %v", err))
	}
	workerResult.Logs = append(workerResult.Logs, "buildOCIDirectory:: Exit()")
	return nil
}

func executeAndLogWindowsScanner(appResource runningapps.Resource, yamlConfig *config.Config, organizationResource organizationpayload.OrganizationPayload, spaceResource spacepayload.SpacePayload, sysdigAPIToken string, workerResult *executionresults.WorkerResult) error {
	var err error
	_ = sysdigAPIToken
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogWindowsScanner:: Enter()"))
	ociDirPath := fmt.Sprintf("%s/oci/%s/%s/%s/%s", yamlConfig.Settings.WorkingDirectory, organizationResource.Name, spaceResource.Name, appResource.GUID, appResource.Name)

	// Append the OCI directory path to the arguments
	filenameUUID := appResource.GUID
	scanResultsPath := fmt.Sprintf("%s/scanResults", yamlConfig.Settings.WorkingDirectory)

	if _, err := os.Stat(scanResultsPath); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(scanResultsPath, os.ModePerm); err != nil {
				return err
			}
		}
	}

	scanResultsFilename := fmt.Sprintf("%s/%s.json", scanResultsPath, filenameUUID)
	scanLogFilename := fmt.Sprintf("%s.log", scanResultsFilename)
	workerResult.ScanResultsFilename = scanResultsFilename
	workerResult.ScanResultsLogFilename = scanLogFilename

	// Split the execution command string into arguments
	var args []string
	args = append(args, "./grype")
	args = append(args, fmt.Sprintf("oci-dir:%s", ociDirPath))
	args = append(args, "-o")
	args = append(args, "json")
	args = append(args, "--file")
	args = append(args, scanResultsFilename)
	args = append(args, "-c")
	args = append(args, "grype.yaml")
	args = append(args, "--by-cve")
	args = append(args, "-v")

	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogWindowsScanner:: Executing: %v", args))

	// Assuming the first argument is the path to the executable
	cmd := exec.Command(args[0], args[1:]...)

	// Create a pipe to the standard err of the cmd

	var stderrPipe io.ReadCloser
	if stderrPipe, err = cmd.StderrPipe(); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogWindowsScanner:: Failed to create stdout pipe: %v", err))
		return err
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogWindowsScanner:: Failed to start cmd: %v", err))
		return err
	}

	// Use a scanner to read the command's stdout line by line
	scanner := bufio.NewScanner(stderrPipe)
	for scanner.Scan() {
		workerResult.Logs = append(workerResult.Logs, scanner.Text())
	}

	// Wait for the command to finish
	if err = cmd.Wait(); err != nil {
		var exiterr *exec.ExitError
		if errors.As(err, &exiterr) {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				exitCode := status.ExitStatus()
				workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogWindowsScanner::Cmd exited with code: %d", exitCode))
				if exitCode > 3 {
					workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogWindowsScanner::Cmd finished with unacceptable error code: %v", exitCode))
					return err
				} else {
					// Handle legitimate exit codes (0 and 1, and any code <= 3) gracefully
					workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogWindowsScanner::Cmd finished with acceptable error code: %v. Continuing...", exitCode))
				}
			}
		}
	}

	// Command executed successfully, exit code 0
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogWindowsScanner::Cmd executed successfully"))
	// Set the JSON file in structure
	workerResult.RunningApp.ResultsFilename = scanResultsFilename
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogWindowsScanner:: Exit()"))
	return nil
}

func executeAndLogSysdigScanner(appResource runningapps.Resource, yamlConfig *config.Config, organizationResource organizationpayload.OrganizationPayload, spaceResource spacepayload.SpacePayload, sysdigAPIToken string, workerResult *executionresults.WorkerResult) error {
	var err error
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner:: Enter()"))

	ociDirPath := fmt.Sprintf("file://%s/oci/%s/%s/%s/%s", yamlConfig.Settings.WorkingDirectory, organizationResource.Name, spaceResource.Name, appResource.GUID, appResource.Name)

	// Append the OCI directory path to the arguments
	filenameUUID := appResource.GUID
	scanResultsPath := fmt.Sprintf("%s/scanResults", yamlConfig.Settings.WorkingDirectory)

	if _, err = os.Stat(scanResultsPath); err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(scanResultsPath, os.ModePerm)
			if err != nil {
				return err
			}
		}
	}

	scanResultsFilename := fmt.Sprintf("%s/%s.json", scanResultsPath, filenameUUID)
	scanLogFilename := fmt.Sprintf("%s.log", scanResultsFilename)
	workerResult.ScanResultsFilename = scanResultsFilename
	workerResult.ScanResultsLogFilename = scanLogFilename

	// Split the configuration command string into arguments
	var args []string
	args = append(args, "./sysdig-cli-scanner")
	args = append(args, "--full-vulns-table")
	args = append(args, "--loglevel=debug")
	if yamlConfig.Settings.Standalone {
		args = append(args, "--standalone")
		args = append(args, "--no-cache")
		args = append(args, fmt.Sprintf("--output-json=%s", scanResultsFilename))
		args = append(args, fmt.Sprintf("--logfile=%s", scanLogFilename))
	} else {
		args = append(args, "--skipupload")
		args = append(args, "--no-cache")
		args = append(args, "--offline-analyzer")
		args = append(args, fmt.Sprintf("--policy=%s", yamlConfig.Config.SysdigPolicy))
		args = append(args, fmt.Sprintf("--json-scan-result=%s", scanResultsFilename))
		args = append(args, fmt.Sprintf("--logfile=%s", scanLogFilename))
		args = append(args, fmt.Sprintf("--apiurl=%s", yamlConfig.Config.SysdigAPIEndpoint))

	}
	args = append(args, ociDirPath)
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner:: Executing: %v", args))

	// Assuming the first argument is the path to the Sysdig CLI executable
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("SECURE_API_TOKEN=%s", sysdigAPIToken))

	// Create a pipe to the standard output of the cmd
	var stdoutPipe io.ReadCloser
	if stdoutPipe, err = cmd.StdoutPipe(); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner:: Failed to create stdout pipe: %v", err))
		return err
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner:: Failed to start cmd: %v", err))
		return err
	}

	// Use a scanner to read the command's stdout line by line
	scanner := bufio.NewScanner(stdoutPipe)
	for scanner.Scan() {
		workerResult.Logs = append(workerResult.Logs, scanner.Text())
	}

	// Wait for the command to finish
	if err = cmd.Wait(); err != nil {
		var exiterr *exec.ExitError
		if errors.As(err, &exiterr) {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				exitCode := status.ExitStatus()
				workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner::Cmd exited with code: %d", exitCode))
				if exitCode > 3 {
					workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner::Cmd finished with unacceptable error code: %v", exitCode))
					return err
				} else {
					// Handle legitimate exit codes (0 and 1, and any code <= 3) gracefully
					workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner::Cmd finished with acceptable error code: %v. Continuing...", exitCode))
				}
			}
		}
	}
	// Command executed successfully, exit code 0
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner::Cmd executed successfully"))
	// Set the JSON file in structure
	workerResult.RunningApp.ResultsFilename = scanResultsFilename
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner:: Exit()"))
	return nil
}

func writeCSV(filename string, data *[][]string) (err error) {
	log.Print("writeCSV:: Enter()")

	log.Printf("writeCSV:: Creating CSV File: %s", filename)
	var file *os.File
	if file, err = os.Create(filename); err != nil {
		log.Printf("writeCSV:: Failed to create CSV file: %v", err)
		return err
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			log.Printf("writeCSV:: Failed to close CSV. ERROR: %v", err)
		}
	}(file)

	writer := csv.NewWriter(file)
	writer.Comma = ','

	for _, record := range *data {
		// Process record to escape quotes or adjust fields as needed
		if err := writer.Write(record); err != nil {
			log.Printf("failed to write record to CSV: %v", err)
			return err
		}
	}
	writer.Flush()
	log.Printf("writeCSV:: Exit()")
	return writer.Error()
}

func generateCSVDataOnline(yamlConfig *config.Config, result *ResultsJSON.ScanResult, executionResult *executionresults.WorkerResult) (csvData [][]string, err error) {
	// Search for the 'BankWest Tanzu Policy' in PolicyEvaluations
	for _, policyEval := range result.Result.PolicyEvaluations {
		if policyEval.Identifier == yamlConfig.Config.SysdigPolicy {
			for _, bundle := range policyEval.Bundles {
				for _, rule := range bundle.Rules {
					for _, failure := range rule.Failures {
						// Assuming pkgIndex is within the bounds of the Packages array
						if failure.PkgIndex >= 0 && failure.PkgIndex < len(result.Result.Packages) {
							pkg := result.Result.Packages[failure.PkgIndex]
							// Assuming vulnInPkgIndex is within the bounds of the Vulns array
							if failure.VulnInPkgIndex >= 0 && failure.VulnInPkgIndex < len(pkg.Vulns) {
								vuln := pkg.Vulns[failure.VulnInPkgIndex]

								// Generate a CVE link if possible
								var cveLink string
								if strings.HasPrefix(strings.ToUpper(vuln.Name), "CVE") {
									cveLink = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.Name)
								}

								// Generate Suggested fix / fixed in version
								var strFixedVersion string
								if pkg.SuggestedFix != "" && vuln.FixedInVersion != "" {
									strFixedVersion = pkg.SuggestedFix
								} else {
									strFixedVersion = vuln.FixedInVersion
								}
								csvData = append(csvData, []string{
									executionResult.RunningApp.Name,
									fmt.Sprintf("%d", executionResult.DeployedRevisionVersion),
									executionResult.DropletSHA256Hash,
									vuln.Severity.Value,
									vuln.Name,
									pkg.Name,
									pkg.Version,
									pkg.Path,
									strFixedVersion,
									vuln.SolutionDate,
									cveLink,
									executionResult.RunningApp.Organization.Name,
									executionResult.RunningApp.Space.Name,
									"",
									time.Now().Format("02/01/2006"),
									"BankWest",
									"",
									"",
									"",
								})
							}
						}
					}
				}
			}
		}
	}
	return csvData, nil
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func generateCSVDataStandalone(yamlConfig *config.Config, result *ResultsJSONOld.ScanResult, executionResult *executionresults.WorkerResult) (csvData [][]string, err error) {

	// Build list of severities to check vulns against (>=)
	var includeSeverities []string
	if yamlConfig.Settings.StandaloneSeverity != "" {
		severity := strings.ToUpper(yamlConfig.Settings.StandaloneSeverity)

		switch severity {
		case "CRITICAL":
			includeSeverities = []string{"CRITICAL"}
		case "HIGH":
			includeSeverities = []string{"CRITICAL", "HIGH"}
		case "MEDIUM":
			includeSeverities = []string{"CRITICAL", "HIGH", "MEDIUM"}
		case "LOW":
			includeSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
		case "NEGLIGIBLE":
			includeSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"}
		}
	}

	for _, pkg := range result.Packages.List {
		for _, vuln := range pkg.Vulnerabilities {

			// Check if we are to include this vuln based off 'policy' parameters, else skip
			if !contains(includeSeverities, strings.ToUpper(vuln.Severity.Label)) {
				continue
			}

			// Check if vuln has fix, if we need a fix date and there is not a solution date, continue with next vuln
			if yamlConfig.Settings.StandaloneHasFix && vuln.SolutionDate == "" {
				continue
			}

			// check for vuln days, ensure it's within our range
			// Build solution date
			var solutionDate string
			var parsedSolutionDate time.Time
			if vuln.SolutionDate != "" {
				if parsedSolutionDate, err = time.Parse(time.RFC3339, vuln.SolutionDate); err != nil {
					solutionDate = "dateParseError"
				} else {
					thresholdDate := time.Now().AddDate(0, 0, -yamlConfig.Settings.StandaloneDaysSinceFix)
					if !parsedSolutionDate.Before(thresholdDate) {
						continue // Solution date is older than the specified days ago, skip this vulnerability
					}
					solutionDate = parsedSolutionDate.Format("02/01/2006") // Format the date as "dd/mm/yyyy"
				}
			}

			// Get URL for link
			var cveLink string
			if vuln.Severity.SourceUrl != "" {
				cveLink = vuln.Severity.SourceUrl
			} else {
				if vuln.CvssScore.SourceUrl == "" {
					cveLink = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.Name)
				} else {
					cveLink = vuln.CvssScore.SourceUrl
				}
			}

			csvData = append(csvData, []string{
				executionResult.RunningApp.Name,
				fmt.Sprintf("%d", executionResult.DeployedRevisionVersion),
				executionResult.DropletSHA256Hash,
				vuln.Severity.Label,
				vuln.Name,
				pkg.Name,
				pkg.Version,
				pkg.PackagePath,
				pkg.SuggestedFix,
				solutionDate,
				cveLink,
				executionResult.RunningApp.Organization.Name,
				executionResult.RunningApp.Space.Name,
				"",
				time.Now().Format("02/01/2006"),
				"BankWest",
				"",
				"",
				"",
			})
		}
	}
	return csvData, nil
}

func extractAndWriteCSV(executionResults *[]executionresults.WorkerResult, yamlConfig *config.Config) (err error) {
	log.Print("extractAndWriteCSV:: Enter()")

	var csvData [][]string

	for _, executionResult := range *executionResults {
		// Extract results
		if executionResult.Result == true {
			var jsonData []byte
			if jsonData, err = os.ReadFile(executionResult.RunningApp.ResultsFilename); err != nil {
				log.Printf("extractAndWriteCSV:: Error reading scan logs for app: %s. ERROR: %v", executionResult.RunningApp.Name, err)
				continue
			}

			var csvDataRow [][]string

			if yamlConfig.Settings.Standalone {
				var resultOld ResultsJSONOld.ScanResult
				if err := json.Unmarshal(jsonData, &resultOld); err != nil {
					log.Printf("extractAndWriteCSV:: Standalone: Error unmarshaling json for app: %s. ERROR: %v", executionResult.RunningApp.Name, err)
					continue
				}
				csvDataRow, _ = generateCSVDataStandalone(yamlConfig, &resultOld, &executionResult)

			} else {
				var result ResultsJSON.ScanResult
				if err := json.Unmarshal(jsonData, &result); err != nil {
					log.Printf("extractAndWriteCSV:: Online: Error unmarshaling json for app: %s. ERROR: %v", executionResult.RunningApp.Name, err)
					continue
				}
				csvDataRow, err = generateCSVDataOnline(yamlConfig, &result, &executionResult)
			}

			// Merge CSV data to existing data
			for _, row := range csvDataRow {
				csvData = append(csvData, row)
			}

		} else {
			log.Printf("extractAndWriteCSV:: App: %s, completion unsuccessful, skipping. Reason: '%s'", executionResult.RunningApp.Name, executionResult.ResultReason)
		}
	}

	//now write the header row
	csvHeaderRow := []string{
		"Image Name",
		"Image Tag",
		"Image Digest",
		"Severity",
		"Vulnerability",
		"Package name",
		"Package Version",
		"Package Path",
		"Fixed In",
		"Observed Fix Date",
		"Link",
		"Cluster",
		"Namespace",
		"Service Owner",
		"Scanned Date",
		"Environment",
		"CI Number",
		"SPG",
		"Platform",
	}

	// Insert Header row first
	csvData = append([][]string{csvHeaderRow}, csvData...)

	// Format the current time to generate the filename
	if err = writeCSV(fmt.Sprintf("%s/%s-Tanzu-Bankwest.csv", yamlConfig.Settings.WorkingDirectory, time.Now().Format("20060102150405")), &csvData); err != nil {
		log.Printf("extractAndWriteCSV:: Could not write CSV.")
		return err
	}
	log.Printf("extractAndWriteCSV:: Exit()")
	return nil
}

func init() {
	// Set the formatter to text
	log.SetFormatter(&log.TextFormatter{
		// Disable timestamp to closely match standard log package output
		DisableTimestamp: false,
		// FullTimestamp ensures the full timestamp is printed
		FullTimestamp: true,
		// Force formatting to be the same regardless of environment
		ForceColors:            true,
		DisableLevelTruncation: true,
		// You can also modify the timestamp format to your liking
		TimestampFormat: "2006-01-02 15:04:05.000",
	})

	// Configure logrus global log settings here for JSON / production
	//log.SetFormatter(&log.JSONFormatter{})
	//log.SetLevel(log.DebugLevel)
}

func processApp(workerNumber int, appResource runningapps.Resource, yamlConfig config.Config) (workerResult executionresults.WorkerResult, err error) {
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Enter() as Worker %d", workerNumber))
	// Getting oAuthToken for thread
	var oAuthToken *oauthtoken.OAuthToken
	if oAuthToken, err = getAccessToken(&yamlConfig, &workerResult); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Error getting OAuth token: %v", err))
		workerResult.ResultReason = "Error getting OAuth token"
		return workerResult, err
	}

	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Obtained OAuth Token, expires in: %+v", oAuthToken.ExpiryTime))

	workerResult.RunningApp = appResource
	workerResult.Result = false

	// Get space information
	var jsonSpace *spacepayload.SpacePayload
	if jsonSpace, err = getSpace(appResource.Name, appResource.Links["space"].Href, oAuthToken, &workerResult); err != nil {
		workerResult.ResultReason = "Failed to get get space"
		workerResult.Logs = append(workerResult.Logs, fmt.Sprint("processApp:: Failed to get get space"))
		return workerResult, err
	}

	// Get organizatino information
	var jsonOrganization *organizationpayload.OrganizationPayload
	if jsonOrganization, err = getOrganization(appResource.Name, jsonSpace.Links["organization"].Href, oAuthToken, &workerResult); err != nil {
		workerResult.ResultReason = "Failed to get 'organization'"
		workerResult.Logs = append(workerResult.Logs, fmt.Sprint("processApp:: Failed to get 'organization'"))
		return workerResult, err
	}

	// Get deployed revision information
	var intDeployedRevisionVersion int64
	if intDeployedRevisionVersion, err = getDeployedRevision(appResource.Name, appResource.Links["deployed_revisions"].Href, oAuthToken, &workerResult); err != nil {
		workerResult.ResultReason = "Failed to get 'deployed_revisions'"
		workerResult.Logs = append(workerResult.Logs, fmt.Sprint("processApp:: Failed to get 'deployed_revisions', setting revision to 0"))
		intDeployedRevisionVersion = 0
	}

	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Found spaceName: '%v', organizationName: '%v', Deployed Version: '%d' for AppName: '%v'", jsonSpace.Name, jsonOrganization.Name, intDeployedRevisionVersion, appResource.Name))

	dropletFilePath := fmt.Sprintf("%s/droplets/%s/%s/%s/%s.tar.gz", yamlConfig.Settings.WorkingDirectory, jsonOrganization.Name, jsonSpace.Name, appResource.GUID, appResource.Name)
	workerResult.DropletFilename = dropletFilePath
	if _, err := os.Stat(dropletFilePath); os.IsNotExist(err) {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Droplet file does not exist: %s, typing to download", dropletFilePath))
		if err = downloadDroplet(appResource, dropletFilePath, oAuthToken, &workerResult); err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Could not download droplet, skipping app '%s'", appResource.Name))
			workerResult.ResultReason = fmt.Sprintf("Could not download droplet, skipping app '%s'", appResource.Name)
			return workerResult, err
		}
	} else {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Droplet for app '%s' already exists (%s.tar.gz), skipping download...", appResource.Name, appResource.Name))
	}

	// Check tha we have the stack for the app.  If not then skip app
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Stack for App '%s': '%s'", appResource.Name, appResource.Lifecycle.Data.Stack))
	if stackPath, ok := yamlConfig.Stacks[appResource.Lifecycle.Data.Stack]; ok {
		if _, err := os.Stat(stackPath); os.IsNotExist(err) {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Stack file for '%s' does not exist at path: '%s'", appResource.Lifecycle.Data.Stack, stackPath))
			workerResult.ResultReason = fmt.Sprintf("Stack file for '%s' does not exist at path: '%s'", appResource.Lifecycle.Data.Stack, stackPath)
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Skipping processing of App: '%s' ", appResource.Name))
			return workerResult, err
		} else {
			// Proceed with using the stack file
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Stack file for '%s' exists at path: '%s'", appResource.Lifecycle.Data.Stack, stackPath))
		}
	} else {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Stack '%s' does not exist in the yamlConfig", appResource.Lifecycle.Data.Stack))
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Skipping processing of App: '%s' ", appResource.Name))
		workerResult.ResultReason = fmt.Sprintf("Stack: '%s' does not exist in the yamlConfig, skipping processing", appResource.Lifecycle.Data.Stack)
		return workerResult, fmt.Errorf("processApp:: Skipping processing of App: '%s'", appResource.Name)
	}

	// Build OCI container
	if err = buildOCIDirectory(&yamlConfig, appResource, jsonSpace, jsonOrganization, yamlConfig.Stacks[appResource.Lifecycle.Data.Stack], dropletFilePath, &workerResult); err != nil {
		workerResult.ResultReason = "Failed to successfully build OCI, check specific output"
		return workerResult, err
	}

	// Execute Sysdig-cli-scanner if linux of grype if windows
	if strings.ToUpper(appResource.Lifecycle.Data.Stack) == "WINDOWS-NOT-IMPLEMENTED-YET" {
		if err = executeAndLogWindowsScanner(appResource, &yamlConfig, *jsonOrganization, *jsonSpace, yamlConfig.Config.SysdigAPIToken, &workerResult); err != nil {
			workerResult.ResultReason = "Failed to successfully execute Windows Scanner, check specifc output"
			return workerResult, err
		}
	} else {
		if err = executeAndLogSysdigScanner(appResource, &yamlConfig, *jsonOrganization, *jsonSpace, yamlConfig.Config.SysdigAPIToken, &workerResult); err != nil {
			workerResult.ResultReason = "Failed to successfully execute Sysdig Scanner, check specifc output"
			return workerResult, err
		}
	}

	workerResult.Result = true

	// Always cleanup if required
	defer func() {
		if yamlConfig.Settings.KeepDroplets == false {
			if err = os.RemoveAll(workerResult.DropletFilename); err != nil {
				workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp Cleanup:: Could not delete droplet: '%s'. Error: '%v'", workerResult.DropletFilename, err))
			}
		}
		if yamlConfig.Settings.KeepOCI == false {
			if err = os.RemoveAll(workerResult.OCIPath); err != nil {
				workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp Cleanup:: Could not delete OCI path: '%s'. Error: %v", workerResult.OCIPath, err))
			}
		}
	}()
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Exit() as Worker %d", workerNumber))
	return workerResult, nil
}

func worker(id int, workQueue <-chan runningapps.Resource, startWorkers <-chan struct{}, resultsChan chan<- executionresults.WorkerResult, yamlConfig config.Config, wg *sync.WaitGroup) {
	defer wg.Done()
	<-startWorkers // Wait for the start signal
	var err error
	for app := range workQueue {
		var result executionresults.WorkerResult
		result.ThreadID = id
		if app.State == "STARTED" {
			if result, err = processApp(id, app, yamlConfig); err != nil {
				result.Logs = append(result.Logs, fmt.Sprintf("worker:: Worker '%d': Error processing app '%s'. Error: %v", id, app.Name, err))
			}
		} else {
			// minimal processing for non-running app
			result.RunningApp = app
			result.Logs = append(result.Logs, fmt.Sprintf("worker:: Worker '%d': app '%s' status != STARTED, skipping", id, app.Name))
			result.ResultReason = fmt.Sprintf("App '%s' not in STARTED state, skipped...", app.Name)
		}
		resultsChan <- result
	}
}

func removeFolder(foldertoRremove string) {
	log.Print("removeFolder:: Enter()")
	log.Printf("removeFolder:: Removing '%s'", foldertoRremove)
	if err := os.RemoveAll(foldertoRremove); err != nil {
		log.Printf("removeFolder:: Could not delete '%s' directory, continuing.  Error: %v", foldertoRremove, err)
	}
	log.Print("removeFolder:: Exit()")
}

func cleanup(yamlConfig *config.Config) {
	log.Printf("cleanup:: Enter()")

	if yamlConfig.Settings.KeepOCI == false {
		removeFolder(fmt.Sprintf("%s/oci", yamlConfig.Settings.WorkingDirectory))
	}

	if yamlConfig.Settings.KeepScanLogs == false {
		removeFolder(fmt.Sprintf("%s/scanResults", yamlConfig.Settings.WorkingDirectory))
	}

	if yamlConfig.Settings.KeepDroplets == false {
		removeFolder(fmt.Sprintf("%s/droplets", yamlConfig.Settings.WorkingDirectory))
	}

	log.Printf("cleanup:: Exit()")
}

func parseCommandLineParameters(yamlConfig *config.Config) {
	log.Print("parse_command_line_parameters:: Enter()")

	var cfUsername string
	var cfPassword string
	var sysdigAPIToken string
	pflag.StringVarP(&cfUsername, "cf-username", "u", "", "CF Username (long-form)")
	pflag.StringVarP(&cfPassword, "cf-password", "p", "", "CF Password (long-form)")
	pflag.StringVarP(&sysdigAPIToken, "sysdig-api-token", "a", "", "Sysdig API Token (long-form)")

	// Parse the flags
	pflag.Parse()

	if cfUsername != "" {
		yamlConfig.Config.CFUsername = cfUsername
		log.Print("parse_command_line_parameters:: Overriding CFUsername with command line")
	}

	if cfPassword != "" {
		yamlConfig.Config.CFPassword = cfPassword
		log.Print("parse_command_line_parameters:: Overriding CFPassword with command line")
	}

	if sysdigAPIToken != "" {
		yamlConfig.Config.SysdigAPIToken = sysdigAPIToken
		log.Print("parse_command_line_parameters:: Overriding sysdigAPIToken with command line")
	}

	log.Print("parse_command_line_parameters:: Exit()")
}

func parseEnvironmentVariables(yamlConfig *config.Config) {
	log.Print("parseEnvironmentVariables:: Enter()")

	var cfUsername string
	var cfPassword string
	var sysdigAPIToken string
	var cfClientID string
	var cfClientSecret string

	cfUsername = os.Getenv("CF_USERNAME")
	cfPassword = os.Getenv("CF_PASSWORD")
	cfClientID = os.Getenv("CF_CLIENTID")
	cfClientSecret = os.Getenv("CF_CLIENTSECRET")

	sysdigAPIToken = os.Getenv("SYSDIG_API_TOKEN")

	// Parse the fla

	if cfUsername != "" {
		yamlConfig.Config.CFUsername = cfUsername
		log.Print("parseEnvironmentVariables:: Overriding CFUsername with environment variable")
	}

	if cfPassword != "" {
		yamlConfig.Config.CFPassword = cfPassword
		log.Print("parseEnvironmentVariables:: Overriding CFPassword with environment variable")
	}

	if sysdigAPIToken != "" {
		yamlConfig.Config.SysdigAPIToken = sysdigAPIToken
		log.Print("parseEnvironmentVariables:: Overriding sysdigAPIToken with environment variable")
	}

	if cfClientID != "" {
		yamlConfig.Config.CFClientID = cfClientID
		log.Print("parseEnvironmentVariables:: Overriding cfClientID with environment variable")
	}

	if cfClientSecret != "" {
		yamlConfig.Config.CFClientSecret = cfClientSecret
		log.Print("parseEnvironmentVariables:: Overriding CFClientSecret with environment variable")
	}

	log.Print("parseEnvironmentVariables:: Exit()")
}
func checkForCLIScanner() (err error) {
	log.Debug("checkForCLIScanner:: Enter()")
	presentWorkingDirectory, err := os.Getwd()
	log.Debugf("checkForCLIScanner:: Checking for 'sysdig-cli-scanner' in %s", presentWorkingDirectory)
	if _, err := os.Stat("sysdig-cli-scanner"); os.IsNotExist(err) {
		if err != nil {
			log.Debug("checkForCLIScanner:: Exit()")
			return err
		}
		log.Debug("checkForCLIScanner:: Exit()")
		return err
	} else {
		log.Debug("checkForCLIScanner:: Exit()")
		return nil
	}
}

func removeMainDB(yamlConfig *config.Config) (err error) {
	log.Info("removeMainDB:: Enter()")
	if yamlConfig.Settings.AlwaysDownloadVulndb == true {
		log.Print("removeMainDB:: Removing maindb due to force download as per config 'always_download_vulndb == true'")
		if err = os.RemoveAll("main.db"); err != nil {
			log.Info("removeMainDB:: Exit()")
			return err
		}
		if err = os.RemoveAll("main.db.meta.json"); err != nil {
			log.Info("removeMainDB:: Exit()")
			return err
		}
	} else {
		log.Info("removeMainDB:: Not removing maindb as per 'always_download_vulndb == false'")
	}
	log.Info("removeMainDB:: Exit()")
	return err
}

func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func downloadMainDB(yamlConfig *config.Config) (statusCode int, err error) {
	log.Debug("downloadMainDB:: Enter()")

	//Remove old scan-logs output, will continue anyway
	if err = os.Remove("scan-logs"); err != nil {
		log.Printf("downloadMainDB:: Failed to delete scan-logs file, continuing anyway. Error: %v", err)
	}

	if _, err := os.Stat("main.db"); err == nil {
		if maindbSize, _ := getDirSize("main.db"); maindbSize < 52428800 {
			log.Printf("downloadMainDB:: main.db exists BUT is only %d bytes, shoud be over 100mb.  Cannot continue", maindbSize)
			log.Fatalf("downloadMainDB:: suggest you delete the main.db folder and let it re-download / copy in place")
		}
	}

	if _, err := os.Stat("main.db"); os.IsNotExist(err) {
		log.Printf("downloadMainDB:: main.db does not exist. Error: %v", err)
		log.Print("downloadMainDB:: main.db does not exist, will attempt to download by running 'sysdig-cli-scanner' in download stub mode.")

		// Split the configuration command string into arguments
		args := strings.Fields("./sysdig-cli-scanner --skipupload --no-cache file://test-image")
		args = append(args, fmt.Sprintf("--apiurl=%s", yamlConfig.Config.SysdigAPIEndpoint))

		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = append(os.Environ(), fmt.Sprintf("SECURE_API_TOKEN=%s", yamlConfig.Config.SysdigAPIToken))

		// Create a pipe to the standard output of the cmd
		var stdoutPipe io.Reader
		if stdoutPipe, err = cmd.StdoutPipe(); err != nil {
			log.Fatalf("downloadMainDB:: Failed to create stdout pipe: %v", err)
		}

		// Start the command
		if err := cmd.Start(); err != nil {
			log.Fatalf("downloadMainDB:: Failed to start cmd: %v", err)
		}

		// Use a scanner to read the command's stdout line by line
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			log.Printf("downloadMainDB:: Stub cmd output: %s", scanner.Text())
		}

		// Wait for command to finish and make sure errorcode is 1
		err = cmd.Wait()
		var exiterr *exec.ExitError
		if errors.As(err, &exiterr) {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				exitCode := status.ExitStatus()
				// Output scan-logs if we are in debug mode
				if yamlConfig.Settings.LogLevel == "DEBUG" {
					var file *os.File
					if file, err = os.Open("scan-logs"); err != nil {
						log.Printf("downloadMainDB:: failed to open file: %v", err)

					}
					defer func(file *os.File) {
						if err := file.Close(); err != nil {
							log.Printf("downloadMainDB:: failed to close scan-logs. Error:: %v", err)
						}
					}(file) // Ensure the file is closed after function return

					// Create a new Scanner for reading the file line by line
					scanner := bufio.NewScanner(file)

					// Loop through all lines of the file
					for scanner.Scan() {
						line := scanner.Text()                                     // Get the current line
						log.Printf("downloadMainDB:: scan-logs output:: %s", line) // Output the line
					}

				}
				if exitCode == 2 {
					log.Printf("downloadMainDB:: Stub execution error code: %d (2 is good)", exitCode)
				} else if exitCode == 3 {
					log.Fatalf("downloadMainDB:: Stub execution error code: %d, Failed to download main.db, cannot continue", exitCode)
				}
			}
		}

		log.Printf("downloadMainDB:: Rechecking for main.db exists")
		if _, err = os.Stat("main.db"); err != nil {
			log.Printf("downloadMainDB:: main.db does not exist, cannot continue, check above for download errors. Erorr: %s", err)
		} else {
			log.Print("downloadMainDB:: main.db exists.  Can continue")
		}
		log.Debug("downloadMainDB:: Exit()")
		return statusCode, err
	}
	log.Debug("downloadMainDB:: main.db still exists, continuing")
	log.Debug("downloadMainDB:: Exit()")
	return 2, nil
}

func createWorkingDirectory(yamlConfig *config.Config) {
	log.Info("createWorkingDirectory:: Enter()")
	if yamlConfig.Settings.WorkingDirectory != "" {
		if err := os.MkdirAll(yamlConfig.Settings.WorkingDirectory, os.ModePerm); err != nil {
			log.Fatalf("main:: Failed to create working directory '%s'. Error: %v", yamlConfig.Settings.WorkingDirectory, err)
		}
	} else {
		log.Info("createWorkingDirectory:: Working directory not set. Defaulting to .")
		yamlConfig.Settings.WorkingDirectory = "."
	}
	log.Info("createWorkingDirectory:: Exit()")
}

var VERSION string

func main() {
	var err error
	// Setting up signal catching
	sigs := make(chan os.Signal, 1)
	// Cleanup done channel to wait for cleanup before exiting
	done := make(chan bool, 1)
	// Register the signals you want to catch
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("main:: Sysdig-Tanzu-Scanner v%s-BW Enter()", VERSION)

	// Parse yaml config file
	var yamlConfig config.Config
	if yamlConfig, err = parseConfigFile(); err != nil {
		log.Fatalf("main:: Could not parse yamlConfig file.  Error: %v", err)
	}
	// Set logging level
	var logLevel log.Level
	if logLevel, err = log.ParseLevel(yamlConfig.Settings.LogLevel); err != nil {
		// Handle the error, perhaps defaulting to a specific log level
		log.Fatalf("main:: Invalid log level specified (%s) in config.yaml: %v", yamlConfig.Settings.LogLevel, err)
	}
	log.SetLevel(logLevel)

	// Parse command line parameters and override config if required
	parseCommandLineParameters(&yamlConfig)
	parseEnvironmentVariables(&yamlConfig)

	defer func() {
		cleanup(&yamlConfig)
	}()

	// This goroutine executes when a signal is caught
	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Printf("main:: Received %v, initiating cleanup...\n", sig)
		cleanup(&yamlConfig)
		done <- true
		os.Exit(-1)
	}()

	// Check if CLI scanner executable is available
	if err = checkForCLIScanner(); err != nil {
		log.Fatalf("main:: Could not find / check if sysdig-cli-scanner was found in current directory. Error: %v", err)
	} else {
		log.Print("main:: sysdig-cli-scanner found. Continuing")
	}

	// Actioning always download logic, delete the DB, so it can be re-downloaded
	if err = removeMainDB(&yamlConfig); err != nil {
		log.Fatalf("main:: Failed to remove Main.db, exiting. Error: %v", err)
	}

	// Predownload main database if not found
	var statusCode int
	if statusCode, err = downloadMainDB(&yamlConfig); err != nil {
		log.Fatalf("main:: Failed to download Main.db, exiting. Statuscode: %d, Error: %v", statusCode, err)
	}
	if statusCode == 2 || statusCode == 0 {
		log.Print("main:: Main.db download completed.")
	} else {
		log.Fatal("main:: Main.db download status != 2, exiting.  Review sysdig-cli-output above for clues.")
	}

	if _, err := os.Stat("main.db"); os.IsNotExist(err) {
		log.Fatalf("main:: Failed to download main.db, exiting. Error: %v", err)
	} else {
		log.Printf("main:: Found main.db (the sysdig vulnerability database), continuing")
	}

	decodeConfigCredentials(&yamlConfig)

	var oAuthToken *oauthtoken.OAuthToken
	if oAuthToken, err = getAccessToken(&yamlConfig, nil); err != nil {
		log.Fatalf("main:: Error getting OAuth token: %v", err)
	}
	log.Printf("main:: Obtained OAuth Token, expires in: %+v	", oAuthToken.ExpiryTime)

	// Create working directory if set
	createWorkingDirectory(&yamlConfig)

	//Generate a list of running apps for all organizations and spaces
	var runningApps []runningapps.Resource
	if runningApps, err = generateRunningApps(&yamlConfig, oAuthToken); err != nil {
		log.Printf("main:: Failed to retrieve running apps. Error: %v", err)
	}

	// Initialize a WaitGroup
	var wg sync.WaitGroup

	workQueue := make(chan runningapps.Resource, len(runningApps))
	resultsChan := make(chan executionresults.WorkerResult, len(runningApps))

	for _, app := range runningApps {
		workQueue <- app
	}
	close(workQueue)

	var numWorkers int
	if runtime.NumCPU() > 6 {
		numWorkers = 4
	} else if runtime.NumCPU() > 2 && runtime.NumCPU() < 6 {
		numWorkers = 2
	} else {
		numWorkers = 1
	}

	// Override above if config tells us to
	if yamlConfig.Settings.ExecutionThreads > 0 {
		log.Printf("main:: Overriding calculated execution threads (%d) with config value: %d", numWorkers, yamlConfig.Settings.ExecutionThreads)
		numWorkers = yamlConfig.Settings.ExecutionThreads
	} else {
		log.Printf("main:: Execution threads (%d)", numWorkers)
	}

	log.Print("")
	log.Print("")
	log.Print("main:: Starting workers. Please wait... Execution results will be begin showing momentarily")

	//Setup starting channel mechanism
	startWorkers := make(chan struct{})

	// Start a predefined number of workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1) // Increment the WaitGroup counter for each worker
		go worker(i, workQueue, startWorkers, resultsChan, yamlConfig, &wg)
	}

	close(startWorkers)

	// Keep results for further post-processing
	var executionResults []executionresults.WorkerResult

	for i := 0; i < len(runningApps); i++ {
		executionResult := <-resultsChan
		// Process result
		for _, line := range executionResult.Logs {
			log.Printf("%s", line)
		}
		// Log all entries to the command line
		log.Printf("main:: Result No: %d/%d, Result from app %s: %v", i, len(runningApps), executionResult.RunningApp.Name, executionResult.Result)
		log.Print("")
		executionResults = append(executionResults, executionResult)
	}

	// Wait for all workers to finish
	wg.Wait()
	// Signal that no more results will be sent - close results channel.
	close(resultsChan)

	// Process CSV
	if err = extractAndWriteCSV(&executionResults, &yamlConfig); err != nil {
		log.Fatalf("main:: Could not write CSV file.  Error: %v", err)
	}

	log.Print("main:: Exit()")
	log.Println("main:: Finished...")
}
