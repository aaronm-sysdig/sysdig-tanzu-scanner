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
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/message"
	"gopkg.in/yaml.v2"
	"io"
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
	"sysdig-tanzu-scanner/types/credentials"
	"sysdig-tanzu-scanner/types/currentdroplet"
	"sysdig-tanzu-scanner/types/deployedrevision"
	"sysdig-tanzu-scanner/types/executionresults"
	"sysdig-tanzu-scanner/types/oauthtoken"
	"sysdig-tanzu-scanner/types/oci"
	"sysdig-tanzu-scanner/types/organizationpayload"
	ResultsJSON "sysdig-tanzu-scanner/types/results"
	"sysdig-tanzu-scanner/types/runningapps"
	"sysdig-tanzu-scanner/types/spacepayload"
	"time"
)

func parseConfigFile() (config.Config, error) {
	log.Print("parseConfigFile:: Enter()")

	tanzuConfig := config.Config{}

	data, err := os.ReadFile("config.yaml")
	if err != nil {
		return config.Config{}, fmt.Errorf("error reading config file: %v", err)
	}

	err = yaml.Unmarshal(data, &tanzuConfig)
	if err != nil {
		return config.Config{}, fmt.Errorf("error parsing config file: %v", err)
	}

	if tanzuConfig.Settings.LogLevel == "" ||
		tanzuConfig.Config.CFAuthEndpoint == "" ||
		tanzuConfig.Config.CFAPIEndpoint == "" ||
		tanzuConfig.Config.SysdigCliCommand == "" ||
		len(tanzuConfig.Stacks) == 0 {
		return config.Config{}, errors.New("config validation failed: missing required fields")
	}

	log.Print("parseConfigFile:: Exit()")
	return tanzuConfig, nil
}

func decodeConfigCredentials(config config.Config, workerResult *executionresults.WorkerResult) (*credentials.Credentials, error) {
	if workerResult != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprint("decodeConfigCredentials:: Enter()"))
	} else {
		log.Print("decodeConfigCredentials:: Enter()")
	}

	// Decode the base64 encoded username
	decodedUsername, err := base64.StdEncoding.DecodeString(config.Config.CFUsername)
	if err != nil {
		return nil, err
	}

	// Decode the base64 encoded password
	decodedPassword, err := base64.StdEncoding.DecodeString(config.Config.CFPassword)
	if err != nil {
		return nil, err
	}

	// Create an instance of Credentials struct with decoded values
	tanzuCredentials := credentials.Credentials{
		Username:        string(decodedUsername),
		Password:        string(decodedPassword),
		CFLoginEndpoint: config.Config.CFAuthEndpoint,
	}

	if workerResult != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprint("decodeConfigCredentials:: Exit()"))
	} else {
		log.Print("decodeConfigCredentials:: Exit()")
	}
	return &tanzuCredentials, nil
}

/*func refreshAccesstoken(config *Config, existingOAuthToken *OAuthToken, creds *Credentials) (*OAuthToken, error) {
	if !existingOAuthToken.IsValid() {
		newOAuthToken, _ := getAccessToken(config, creds)
		return newOAuthToken, nil
	} else {
		return existingOAuthToken, nil
	}
}*/

func getAccessToken(config *config.Config, creds *credentials.Credentials) (*oauthtoken.OAuthToken, error) {
	configLogin := sysdighttp.DefaultSysdigRequestConfig()
	configLogin.Method = "POST"
	configLogin.URL = config.Config.CFAuthEndpoint
	configLogin.Verify = false
	configLogin.Auth = [2]string{"cf", ""}
	configLogin.Headers = map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	configLogin.Data = map[string]string{
		"username":   creds.Username,
		"password":   creds.Password,
		"grant_type": "password",
	}

	objResponse, err := sysdighttp.SysdigRequest(configLogin)
	var loginBody oauthtoken.OAuthToken
	err = sysdighttp.ResponseBodyToJson(objResponse, &loginBody)
	if err != nil {
		log.Fatalf("ResponseBodyToJson error: %v", err)
	}
	defer objResponse.Body.Close()

	// Calculate the expiry time based on the current time and expires_in value
	loginBody.ExpiryTime = time.Now().Add(time.Second * time.Duration(loginBody.ExpiresIn))

	return &loginBody, nil
}

/*
func getOrganizations(yamlConfig *config.Config, authToken *oauthtoken.OAuthToken) (*organizationpayload.OrganizationsPayload, error) {
	// Get list of Organizations
	log.Printf("getOrganizations:: Enter()")

	configOrgs := sysdighttp.DefaultSysdigRequestConfig()
	configOrgs.URL = yamlConfig.Config.CFAPIEndpoint + "/v3/organizations?per_page=5000"
	configOrgs.Headers = map[string]string{
		"authorization": "bearer " + authToken.AccessToken,
	}
	objResponse, err := sysdighttp.SysdigRequest(configOrgs) // Corrected variable name
	if err != nil {
		return nil, fmt.Errorf("getOrganizations:: Failed to get organizations. Error: %v", err)
	}
	var jsonOrganizations organizationpayload.OrganizationsPayload
	err = sysdighttp.ResponseBodyToJson(objResponse, &jsonOrganizations)
	if err != nil {
		return nil, fmt.Errorf("getOrganizations:: ResponseBodyToJson error: %v", err)
	}
	log.Printf("getOrganizations:: Exit()")
	return &jsonOrganizations, nil
}
*/

/*func _getRunningAppsForOrg(organizationGUID string, organizationName string, yamlConfig *config.Config, authToken *oauthtoken.OAuthToken) (*[]runningapps.Resource, error) {
	// Get list of running apps for an organization
	log.Printf("getRunningAppsForOrg:: Enter()")
	configOrgApps := sysdighttp.DefaultSysdigRequestConfig()
	configOrgApps.URL = yamlConfig.Config.CFAPIEndpoint + fmt.Sprintf("/v3/apps?organization_guids=%s&per_page=5000&lifecycle_type=buildpack", organizationGUID)
	configOrgApps.Headers = map[string]string{
		"authorization": "bearer " + authToken.AccessToken,
	}
	objResponse, err := sysdighttp.SysdigRequest(configOrgApps) // Corrected variable name
	if err != nil {
		return nil, fmt.Errorf("getRunningAppsForOrg:: Failed to get running apps for org: %s. Error: %v", organizationName, err)
	}

	var jsonRunningApps runningapps.RunningApps
	err = sysdighttp.ResponseBodyToJson(objResponse, &jsonRunningApps)
	if err != nil {
		return nil, fmt.Errorf("getRunningAppsForOrg:: ResponseBodyToJson error: %v", err)
	}
	log.Printf("getRunningAppsForOrg:: Exit()")
	return &jsonRunningApps.Resources, nil
}*/

func generateRunningApps(yamlConfig *config.Config, authToken *oauthtoken.OAuthToken, creds *credentials.Credentials) ([]runningapps.Resource, error) {
	log.Print("generateRunningApps:: Enter()")
	var err error

	if !authToken.IsValid() {
		log.Print("getAccessToken:: Enter()")
		authToken, err = getAccessToken(yamlConfig, creds)
		log.Print("getAccessToken:: Exit()")

		if err != nil {
			log.Fatalf("generateRunningApps:: Failed to refresh OAuthToken. Error: %v", err)
		}
	}

	configOrgApps := sysdighttp.DefaultSysdigRequestConfig()
	configOrgApps.URL = fmt.Sprintf("%s/v3/apps?lifecycle_type=buildpack&per_page=5000", yamlConfig.Config.CFAPIEndpoint)
	configOrgApps.Headers = map[string]string{
		"authorization": "bearer " + authToken.AccessToken,
	}
	objResponse, err := sysdighttp.SysdigRequest(configOrgApps) // Corrected variable name
	if err != nil {
		return nil, fmt.Errorf("generateRunningApps:: Failed to get running apps. Error: %s", err)
	}

	var jsonRunningAppsComplete runningapps.RunningApps
	err = sysdighttp.ResponseBodyToJson(objResponse, &jsonRunningAppsComplete)
	if err != nil {
		return nil, fmt.Errorf("generateRunningApps:: ResponseBodyToJson error: %v", err)
	}
	log.Print("generateRunningApps:: Exit()")
	return jsonRunningAppsComplete.Resources, nil

	/*
			jsonOrganizations, err := getOrganizations(yamlConfig, authToken)
			if err != nil {
				log.Printf("generateRunningApps:: Could not retrieve list of organizations. Cannot continue. Error: %v", err)
				return nil, err
			}

			for idx, organization := range jsonOrganizations.Resources {
				log.Printf("generateRunningApps:: Processing organization %d/%d: %s", idx, len(jsonOrganizations.Resources)-1, organization.Name)
				jsonOrgApps, err := getRunningAppsForOrg(organization.GUID, organization.Name, yamlConfig, authToken)
				if err != nil {
					log.Printf("generateRunningApps:: Could not retrieve apps for org: %s. Error: %v", organization.Name, err)
					return nil, err // Handle the error appropriately.
				}
				for _, app := range *jsonOrgApps {
					log.Printf("generateRunningApps:: Appending app to running Apps: %s", app.Name)
				}
				jsonRunningApps = append(jsonRunningApps, *jsonOrgApps...)
			}
		return jsonRunningApps, nil // Return the accumulated slice and nil as the error.
	*/
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
	objSpaceResponse, err := sysdighttp.SysdigRequest(configSpace)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getSpaceName:: Failed to exequte query to get space for %v.  Error: %v", appName, err))
		return nil, err
	}
	err = sysdighttp.ResponseBodyToJson(objSpaceResponse, &jsonSpace)
	workerResult.RunningApp.Space = *jsonSpace
	if err != nil || len(jsonSpace.Name) == 0 {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getSpaceName:: Failed to get space for %v.  Error: %v", appName, err))
		return nil, err
	}
	if len(jsonSpace.Name) == 0 {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getSpaceName:: space length is 0 for %v", appName))
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
	objDeployedRevisionResponse, err := sysdighttp.SysdigRequest(configDeployedRevision)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getDeployedRevision:: Failed to exequte query to get deployed revision for %v.  Error: %v", appName, err))
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

	configSpace := sysdighttp.DefaultSysdigRequestConfig()
	configSpace.URL = organizationURL
	configSpace.Method = "GET"
	configSpace.Verify = false
	configSpace.Headers = map[string]string{
		"authorization": "bearer " + oAuthToken.AccessToken,
	}
	objOrganizationResponse, err := sysdighttp.SysdigRequest(configSpace)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getOrganization:: Failed to exequte query to get organization for %v.  Error: %v", appName, err))
		return nil, err
	}
	err = sysdighttp.ResponseBodyToJson(objOrganizationResponse, &jsonOrganization)
	workerResult.RunningApp.Organization = *jsonOrganization
	if err != nil || len(jsonOrganization.Name) == 0 {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getOrganization:: Failed to get space for %v.  Error: %v", appName, err))
		return nil, err
	}
	if len(jsonOrganization.Name) == 0 {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("getOrganization:: Organization length is 0 for %v", appName))
		return nil, err
	}

	workerResult.Logs = append(workerResult.Logs, "getOrganization:: Exit()")
	return jsonOrganization, nil
}

func downloadDroplet(app runningapps.Resource, dropletFilePath string, authToken *oauthtoken.OAuthToken, workerResult *executionresults.WorkerResult) error {
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

	objCurrentDropletResponse, err := sysdighttp.SysdigRequest(configCurrentDroplet)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to get droplet info: %v", err))
		return err
	}
	defer objCurrentDropletResponse.Body.Close()

	var jsonCurrentDroplet currentdroplet.CurrentDroplet
	err = sysdighttp.ResponseBodyToJson(objCurrentDropletResponse, &jsonCurrentDroplet)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to get download droplet link for %s", app.Name))
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
	objDownloadDroplet, err := sysdighttp.SysdigRequest(configDownload)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to download droplet for app: %s. Error: : %v", app.Name, err))
		return err
	}
	defer objDownloadDroplet.Body.Close()

	// Create the droplet file
	dropletFile, err := os.Create(dropletFilePath)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to create droplet file: %v", err))
		return err
	}
	defer func(dropletFile *os.File) {
		err := dropletFile.Close()
		if err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Failed to close droplet file handler. ERROR: %v", err))
		}
	}(dropletFile)

	// Write the response body to file
	workerResult.Logs = append(workerResult.Logs, "downloadDroplet:: Starting to download droplet")
	bytesCopied, err := io.Copy(dropletFile, objDownloadDroplet.Body)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("Failed to write droplet to file: %v", err))
		return err
	}
	workerResult.Logs = append(workerResult.Logs, "downloadDroplet:: Droplet download complete")
	p := message.NewPrinter(message.MatchLanguage("en"))
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Number of bytes written to file: %s", p.Sprintf("%d", bytesCopied)))
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("downloadDroplet:: Exit()"))
	return nil
}

func calculateSHA256(filePath string, workerResult *executionresults.WorkerResult) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
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
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func(in *os.File) {
		err := in.Close()
		if err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("copyFile:: Unable to close source file. ERROR: %v", err))
		}
	}(in)

	// Create the destination file for writing. Create will truncate it if it already exists.
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func(out *os.File) {
		err := out.Close()
		if err != nil {
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
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
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
	jsonBytes, err := json.Marshal(data)
	if err != nil {
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
		relativePath, err := filepath.Rel(startPath, path)
		if err != nil {
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

func buildOCIDirectory(appResource runningapps.Resource,
	spaceResource *spacepayload.SpacePayload,
	organizationResource *organizationpayload.OrganizationPayload,
	stackFilePath string,
	dropletFilePath string,
	workerResult *executionresults.WorkerResult) error {
	var err error

	workerResult.Logs = append(workerResult.Logs, "buildOCIDirectory:: Enter()")
	ociPath := fmt.Sprintf("oci/%s/%s/%s", organizationResource.Name, spaceResource.Name, appResource.Name)
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
	stackSHA256, err := calculateSHA256(stackFilePath, workerResult)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to calculate SHA256 for stack file: %v", err))
		return err
	}
	stackFileInfo, err := os.Stat(stackFilePath)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Error getting file information: %v", err))
		return err
	}

	dropletSHA256, err := calculateSHA256(dropletFilePath, workerResult)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to calculate SHA256 for droplet file: %v", err))
		return err
	}
	workerResult.DropletSHA256Hash = fmt.Sprintf("sha256:%s", dropletSHA256)
	dropletFileInfo, err := os.Stat(dropletFilePath)
	if err != nil {
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

	configBytes, err := json.MarshalIndent(configJSONData, "", "  ")
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Error marshaling config.json: %v", err))
		return err
	}
	configSHA256 := calculateSHA256FromBytes(configBytes)
	configFilePath := filepath.Join(ociPath, "blobs", "sha256", configSHA256)
	if err := os.WriteFile(configFilePath, configBytes, 0644); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Error writing config.json: %v", err))
		return err
	}

	configFileInfo, err := os.Stat(configFilePath)
	if err != nil {
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

	manifestSha256, err := calculateSHA256ForJSON(manifestJSONData)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to calculate SHA256 for manifest JSON: %v", err))
	}
	manifestJSONPath := filepath.Join(ociPath, "blobs/sha256", manifestSha256)
	if err := writeJSONToFile(manifestJSONPath, manifestJSONData, workerResult); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to write manifest.json: %v", err))
	}

	manifestFileInfo, err := os.Stat(manifestJSONPath)
	if err != nil {
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

	//indexSha256, err := calculateSHA256ForJSON(indexJSONData)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to calculate SHA256 for index JSON: %v", err))
	}
	indexJSONPath := filepath.Join(ociPath, "index.json")
	if err := writeJSONToFile(indexJSONPath, indexJSONData, workerResult); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to write index.json: %v", err))
	}

	ociLayout := map[string]string{
		"imageLayoutVersion": "1.0.0",
	}

	ociLayoutFilePath := filepath.Join(ociPath, "oci-layout")
	file, err := os.Create(ociLayoutFilePath)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to create oci-layout file: %v", err))
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to close oci-layout file: %v", err))
		}
	}(file)

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(ociLayout); err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Failed to write oci-layout JSON: %v", err))
	}

	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("buildOCIDirectory:: Writing oci-layout to: %s", ociLayoutFilePath))
	err = logDirectoryTree(ociPath, workerResult)
	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("logDirectoryTree:: Error: %v", err))
	}
	workerResult.Logs = append(workerResult.Logs, "buildOCIDirectory:: Exit()")
	return nil
}

func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current directory: %v", err)
	}
	return dir
}

func executeAndLogSysdigScanner(appResource runningapps.Resource, yamlConfig *config.Config, organizationResource organizationpayload.OrganizationPayload, spaceResource spacepayload.SpacePayload, sysdigCLICommand string, sysdigAPIToken string, workerResult *executionresults.WorkerResult) error {

	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner:: Enter()"))

	ociDirPath := fmt.Sprintf("file://%s/oci/%s/%s/%s", getCurrentDir(), organizationResource.Name, spaceResource.Name, appResource.Name)
	// Split the configuration command string into arguments
	args := strings.Fields(sysdigCLICommand)

	// Append the OCI directory path to the arguments
	filenameUUID := uuid.New()
	scanResultsPath := "scanResults"

	_, err := os.Stat(scanResultsPath)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.MkdirAll(scanResultsPath, os.ModePerm)
			if err != nil {
				return err
			}
		}
	}

	scanResultsFilename := fmt.Sprintf("%s/%s.json", scanResultsPath, filenameUUID.String())
	scanLogFilename := fmt.Sprintf("%s.log", scanResultsFilename)
	workerResult.ScanResultsFilename = scanResultsFilename
	workerResult.ScanResultsLogFilename = scanLogFilename

	args = append(args, fmt.Sprintf("--policy=%s", yamlConfig.Config.SysdigPolicy))
	args = append(args, fmt.Sprintf("--json-scan-result=%s", scanResultsFilename))
	args = append(args, fmt.Sprintf("--logfile=%s", scanLogFilename))
	args = append(args, fmt.Sprintf("--apiurl=%s", yamlConfig.Config.SysdigAPIEndpoint))

	args = append(args, ociDirPath)
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner:: Executing: %v", args))

	// Assuming the first argument is the path to the Sysdig CLI executable
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("SECURE_API_TOKEN=%s", sysdigAPIToken))

	// Create a pipe to the standard output of the cmd
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
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
	err = cmd.Wait()
	if err != nil {
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
	} else {
		// Command executed successfully, exit code 0
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner::Cmd executed successfully"))
		return err
	}

	// Read in the Results file to our construct

	// Set the JSON file in structure
	workerResult.RunningApp.ResultsFilename = scanResultsFilename
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("executeAndLogSysdigScanner:: Exit()"))
	return nil
}

func writeCSV(filename string, data *[][]string) (err error) {
	log.Print("writeCSV:: Enter()")

	file, err := os.Create(filename)
	log.Printf("writeCSV:: Creating CSV File: %s", filename)
	if err != nil {
		log.Printf("writeCSV:: Failed to create CSV file: %v", err)
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("writeCSV:: Failed to close CSV. ERROR: %v", err)
		}
	}(file)

	writer := csv.NewWriter(file)
	writer.Comma = ',' // Specify delimiter if different from ','

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

func extractAndWriteCSV(executionResults *[]executionresults.WorkerResult,
	yamlConfig *config.Config) error {
	log.Print("extractAndWriteCSV:: Enter()")

	var csvData [][]string

	for _, executionResult := range *executionResults {
		// Extract results
		if executionResult.Success == true {
			jsonData, err := os.ReadFile(executionResult.RunningApp.ResultsFilename)
			if err != nil {
				log.Printf("extractAndWriteCSV:: Error reading scan logs for app: %s. ERROR: %v", executionResult.RunningApp.Name, err)
				continue
			}

			var result ResultsJSON.ScanResult
			if err := json.Unmarshal(jsonData, &result); err != nil {
				log.Printf("extractAndWriteCSV:: Error unmarshaling json for app: %s. ERROR: %v", executionResult.RunningApp.Name, err)
				continue
			}
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
											cveLink = fmt.Sprintf("https: //nvd.nist.gov/vuln/detail/%s", vuln.Name)
										}

										// Generate Suggested fix / fixed in version
										var strFixedVersion string
										if pkg.SuggestedFix != "" && vuln.FixedInVersion != "" {
											strFixedVersion = pkg.SuggestedFix
										} else {
											strFixedVersion = vuln.FixedInVersion
										}

										csvData = append(csvData, []string{
											executionResult.DropletFilename,
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
		} else {
			log.Printf("extractAndWriteCSV:: App: %s, completion unsuccessful, skipping", executionResult.RunningApp.Name)
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
	err := writeCSV(fmt.Sprintf("%s-Tanzu-Bankwest.csv", time.Now().Format("20060102150405")), &csvData)
	if err != nil {
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

func processApp(appResource runningapps.Resource, yamlConfig config.Config, threadID int) (workerResult executionresults.WorkerResult, err error) {
	workerResult.Logs = append(workerResult.Logs, "processApp:: Enter()")

	// Getting oAuthToken for thread
	authCredentials, err := decodeConfigCredentials(yamlConfig, &workerResult)
	workerResult.Logs = append(workerResult.Logs, "getAccessToken:: Enter()")
	oAuthToken, err := getAccessToken(&yamlConfig, authCredentials)
	workerResult.Logs = append(workerResult.Logs, "getAccessToken:: Exit()")

	if err != nil {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Error getting OAuth token: %v", err))
		return workerResult, err
	}
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Obtained OAuth Token, expires in: %+v", oAuthToken.ExpiryTime))

	workerResult.RunningApp = appResource
	workerResult.Success = false

	// Get space information
	jsonSpace, err := getSpace(appResource.Name, appResource.Links["space"].Href, oAuthToken, &workerResult)
	if err != nil {
		return workerResult, err
	}

	// Get organizatino information
	jsonOrganization, err := getOrganization(appResource.Name, jsonSpace.Links["organization"].Href, oAuthToken, &workerResult)
	if err != nil {
		return workerResult, err
	}

	// Get deployed revision information

	intDeployedRevisionVersion, err := getDeployedRevision(appResource.Name, appResource.Links["deployed_revisions"].Href, oAuthToken, &workerResult)
	if err != nil {
		return workerResult, err
	}

	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Found spaceName: %v, organizationName: %v, Deployed Version: %d for AppName: %v", jsonSpace.Name, jsonOrganization.Name, intDeployedRevisionVersion, appResource.Name))

	dropletFilePath := fmt.Sprintf("droplets/%v/%v/%v.tar.gz", jsonOrganization.Name, jsonSpace.Name, appResource.Name)
	workerResult.DropletFilename = dropletFilePath
	if _, err := os.Stat(dropletFilePath); os.IsNotExist(err) {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Droplet file does not exist: %s, typing to download", dropletFilePath))
		err = downloadDroplet(appResource, dropletFilePath, oAuthToken, &workerResult)
		if err != nil {
			workerResult.Logs = append(workerResult.Logs, "processApp:: Could not download droplet, skipping app")
			return workerResult, err
		}
	} else {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Droplet for app '%s' already exists (%s.tar.gz), skipping download...", appResource.Name, appResource.Name))
	}

	// Check tha we have the stack for the app.  If not then skip app
	workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Stack for App %s: %s", appResource.Name, appResource.Lifecycle.Data.Stack))
	if stackPath, ok := yamlConfig.Stacks[appResource.Lifecycle.Data.Stack]; ok {
		if _, err := os.Stat(stackPath); os.IsNotExist(err) {
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Stack file for '%s' does not exist at path: %s", appResource.Lifecycle.Data.Stack, stackPath))
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Skipping processing of App: %s ", appResource.Name))
			return workerResult, err
		} else {
			// Proceed with using the stack file
			workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Stack file for '%s' exists at path: %s", appResource.Lifecycle.Data.Stack, stackPath))
		}
	} else {
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Stack '%s' does not exist in the yamlConfig", appResource.Lifecycle.Data.Stack))
		workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp:: Skipping processing of App: %s ", appResource.Name))
		return workerResult, fmt.Errorf("processApp:: Skipping processing of App: %s", appResource.Name)
	}

	// Build OCI container
	err = buildOCIDirectory(appResource, jsonSpace, jsonOrganization, yamlConfig.Stacks[appResource.Lifecycle.Data.Stack], dropletFilePath, &workerResult)
	if err != nil {
		return workerResult, err
	}

	err = executeAndLogSysdigScanner(appResource, &yamlConfig, *jsonOrganization, *jsonSpace, yamlConfig.Config.SysdigCliCommand, yamlConfig.Config.SysdigAPIToken, &workerResult)
	if err != nil {
		return workerResult, err
	}
	workerResult.Success = true
	workerResult.ThreadID = threadID

	// Always cleanup if required
	defer func() {
		if yamlConfig.Settings.KeepDroplets == false {
			err = os.RemoveAll(workerResult.DropletFilename)
			if err != nil {
				workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp Cleanup:: Could not delete droplet: %s. Error: %v", workerResult.DropletFilename, err))
			}
		}
		if yamlConfig.Settings.KeepOCI == false {
			err = os.RemoveAll(workerResult.OCIPath)
			if err != nil {
				workerResult.Logs = append(workerResult.Logs, fmt.Sprintf("processApp Cleanup:: Could not delete OCI path: %s. Error: %v", workerResult.OCIPath, err))
			}
		}
	}()

	return workerResult, nil
}

func worker(id int, workQueue <-chan runningapps.Resource, resultsChan chan<- executionresults.WorkerResult, yamlConfig config.Config, wg *sync.WaitGroup) {
	defer wg.Done()
	var result executionresults.WorkerResult
	var err error
	for app := range workQueue {
		if app.State == "STARTED" {
			result, err = processApp(app, yamlConfig, id)
			if err != nil {
				result.Logs = append(result.Logs, fmt.Sprintf("Worker %d: Error processing app: %v", id, err))
			}
		}
		resultsChan <- result
	}
}

func cleanup(yamlConfig *config.Config) {
	var err error
	if yamlConfig.Settings.KeepOCI == false {
		log.Print("main:: Deleting OCI directory")
		err = os.RemoveAll("oci")
		if err != nil {
			log.Printf("cleanup:: Could not delete OCI directory.  Error: %v", err)
		}
	}

	if yamlConfig.Settings.KeepScanLogs == false {
		log.Print("main:: Deleting Scan Logs directory")
		err = os.RemoveAll("scanResults")
		if err != nil {
			log.Printf("cleanup:: Could not delete scanResults folder.  Error: %v", err)
		}
	}

	if yamlConfig.Settings.KeepDroplets == false {
		log.Print("main:: Deleting Droplets directory")
		err = os.RemoveAll("droplets")
		if err != nil {
			log.Printf("cleanup:: Could not delete droplets folder.  Error: %v", err)
		}
	}
}

func main() {
	// Setting up signal catching
	sigs := make(chan os.Signal, 1)
	// Cleanup done channel to wait for cleanup before exiting
	done := make(chan bool, 1)
	// Register the signals you want to catch
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.Print("main:: Sysdig-Tanzu-Scanner v1.2.1-BW Enter()")

	// Log an info message.
	log.Println("Attempting to parse yamlConfig file")

	yamlConfig, err := parseConfigFile()
	if err != nil {
		log.Fatalf("main:: Could not parse yamlConfig file.  Error: %v", err)
	}

	defer func() {
		cleanup(&yamlConfig)
	}()

	// This goroutine executes when a signal is caught
	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Printf("Received %v, initiating cleanup...\n", sig)
		cleanup(&yamlConfig)
		done <- true
		os.Exit(-1)
	}()

	// Check if CLI scanner executable is available
	if _, err := os.Stat("sysdig-cli-scanner"); os.IsNotExist(err) {
		presentWorkingDirectory, err := os.Getwd()
		if err != nil {
			log.Printf("main:: Error checking if CLI scanner exists. Error: %v", err)
		}
		log.Fatalf("main:: Sysdig CLI Scanner (sysdig-cli-scanner) has not been found in: %s", presentWorkingDirectory)
	} else {
		log.Printf("main:: Found sysdig-cli-scanner in current directory, continuing")
	}

	// Actioning always download logic, delete the DB, so it can be re-downloaded
	if yamlConfig.Settings.AlwaysDownloadVulndb == true {
		log.Print("main:: Removing maindb due to force download as per config 'always_download_vulndb'")
		err = os.RemoveAll("main.db")
		err = os.RemoveAll("main.db.meta.json")
	}

	// Predownload main database if not found
	if _, err := os.Stat("main.db"); os.IsNotExist(err) {
		log.Printf("main:: main.db does not exist. Error: %v", err)
		log.Print("main:: main.db does not exist, will attempt to download by running Sysdig-cli-scanner in stub mode.")

		// Split the configuration command string into arguments
		args := strings.Fields("./sysdig-cli-scanner --skipupload --no-cache docker://test-image")
		args = append(args, fmt.Sprintf("--apiurl=%s", yamlConfig.Config.SysdigAPIEndpoint))

		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = append(os.Environ(), fmt.Sprintf("SECURE_API_TOKEN=%s", yamlConfig.Config.SysdigAPIToken))

		// Start the command
		if err := cmd.Start(); err != nil {
			log.Fatalf("main:: Failed to start cmd: %v", err)

		}
		// Wait for command to finish and make sure errorcode is 1
		err = cmd.Wait()
		var exiterr *exec.ExitError
		if errors.As(err, &exiterr) {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				exitCode := status.ExitStatus()
				log.Printf("main:: Stub execution error code: %d (2 is good)", exitCode)
			}
		}
	}

	if _, err := os.Stat("main.db"); os.IsNotExist(err) {
		log.Fatalf("main:: Failed to download main.db, exiting. Error: %v", err)
	} else {
		log.Printf("main:: Found main.db (the sysdig vulnerability database), continuing")
	}

	authCredentials, err := decodeConfigCredentials(yamlConfig, nil)
	if err != nil {
		log.Fatalf("main:: Could not decode yamlConfig credentials.  Error: %v", err)
	}

	log.Println(yamlConfig)

	log.Print("getAccessToken:: Enter()")
	oAuthToken, err := getAccessToken(&yamlConfig, authCredentials)
	log.Print("getAccessToken:: Exit()")

	if err != nil {
		log.Fatalf("main:: Error getting OAuth token: %v", err)
	}
	log.Printf("main:: Obtained OAuth Token, expires in: %+v	", oAuthToken.ExpiryTime)

	// Create Results directory
	if err := os.MkdirAll("results", os.ModePerm); err != nil {
		log.Fatalf("main:: Failed to create results directory: %v", err)
	}

	//Generate a list of running apps for all organizations and spaces
	runningApps, err := generateRunningApps(&yamlConfig, oAuthToken, authCredentials)

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
	}
	// Start a predefined number of workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1) // Increment the WaitGroup counter for each worker
		go worker(i, workQueue, resultsChan, yamlConfig, &wg)
	}
	// Keep results for further post-processing
	var executionResults []executionresults.WorkerResult

	for i := 0; i < len(runningApps); i++ {
		result := <-resultsChan
		// Process result
		//logEntries := strings.Join(result.Logs, "\n")
		for _, line := range result.Logs {
			log.Printf("%s", line)
		}
		// Log all entries to the command line
		//log.Printf("main::Logs from %s.  %s", result.RunningApp.Name, logEntries)
		log.Printf("main:: Thread: %d, Result from app %s: %v", i, result.RunningApp.Name, result.Success)
		log.Print("")
		executionResults = append(executionResults, result)
	}

	// Wait for all workers to finish
	wg.Wait()
	// Signal that no more results will be sent - close results channel
	close(resultsChan)

	// Process CSV
	err = extractAndWriteCSV(&executionResults, &yamlConfig)
	if err != nil {
		log.Fatalf("main:: Could not write CSV file.  Error: %v", err)
	}

	log.Print("main:: Exit()")
	log.Println("Finished...")
}
