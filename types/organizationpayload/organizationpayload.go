package organizationpayload

import (
	"time"
)

// OrganizationPayload reflects the structure of a single organization.

// OrganizationsPayload is used to unmarshal the list of organizations from the JSON response.
type OrganizationsPayload struct {
	Pagination Pagination            `json:"pagination"`
	Resources  []OrganizationPayload `json:"resources"`
}

type OrganizationPayload struct {
	GUID          string          `json:"guid"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Name          string          `json:"name"`
	Suspended     bool            `json:"suspended"`
	Relationships Relationships   `json:"relationships"`
	Metadata      Metadata        `json:"metadata"`
	Links         map[string]Link `json:"links"`
}

type Pagination struct {
	TotalResults int   `json:"total_results"`
	TotalPages   int   `json:"total_pages"`
	First        Link  `json:"first"`
	Last         Link  `json:"last"`
	Next         *Link `json:"next"`     // Using pointer to handle null
	Previous     *Link `json:"previous"` // Using pointer to handle null
}

type Relationships struct {
	Quota RelationshipData `json:"quota"`
}

type RelationshipData struct {
	Data GUIDData `json:"data"`
}

type GUIDData struct {
	GUID string `json:"guid"`
}

type Metadata struct {
	Labels      map[string]interface{} `json:"labels"`
	Annotations map[string]interface{} `json:"annotations"`
}

type Link struct {
	Href string `json:"href"`
}
