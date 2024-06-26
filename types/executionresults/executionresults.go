package executionresults

import (
	"sysdig-tanzu-scanner/types/runningapps"
)

type WorkerResult struct {
	Result                  bool
	ResultReason            string
	Logs                    []string
	ThreadID                int
	OCIPath                 string
	ScanResultsFilename     string
	ScanResultsLogFilename  string
	DropletFilename         string
	DropletSHA256Hash       string
	RunningApp              runningapps.Resource
	DeployedRevisionVersion int64
}
