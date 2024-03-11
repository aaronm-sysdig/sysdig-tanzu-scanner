package runningapps

import (
	"sysdig-tanzu-scanner/types/organizationpayload"
	"sysdig-tanzu-scanner/types/spacepayload"
	"time"
)

type RunningApps struct {
	Pagination Pagination `json:"pagination"`
	Resources  []Resource `json:"resources"`
}

type Pagination struct {
	TotalResults int   `json:"total_results"`
	TotalPages   int   `json:"total_pages"`
	First        Link  `json:"first"`
	Last         Link  `json:"last"`
	Next         *Link `json:"next"`
	Previous     *Link `json:"previous"`
}

type Link struct {
	Href string `json:"href"`
}

type Resource struct {
	GUID            string          `json:"guid"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	Name            string          `json:"name"`
	State           string          `json:"state"`
	Lifecycle       Lifecycle       `json:"lifecycle"`
	Relationships   Relationships   `json:"relationships"`
	Metadata        Metadata        `json:"metadata"`
	Links           map[string]Link `json:"links"`
	Space           spacepayload.SpacePayload
	Organization    organizationpayload.OrganizationPayload
	ResultsFilename string
}

type Lifecycle struct {
	Type string `json:"type"`
	Data Data   `json:"data"`
}

type Data struct {
	Buildpacks []string `json:"buildpacks"`
	Stack      string   `json:"stack"`
}

type Relationships struct {
	Space Space `json:"space"`
}

type Space struct {
	Data SpaceData `json:"data"`
}

type SpaceData struct {
	GUID string `json:"guid"`
}

type Metadata struct {
	Labels      map[string]interface{} `json:"labels"`
	Annotations map[string]interface{} `json:"annotations"`
}
