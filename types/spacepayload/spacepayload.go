package spacepayload

import (
	"time"
)

type SpacePayload struct {
	GUID          string          `json:"guid"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Name          string          `json:"name"`
	Relationships Relationships   `json:"relationships"`
	Metadata      Metadata        `json:"metadata"`
	Links         map[string]Link `json:"links"`
}

type Relationships struct {
	Organization RelationshipData  `json:"organization"`
	Quota        *RelationshipData `json:"quota"`
}

type RelationshipData struct {
	Data *GUIDData `json:"data"`
}

type GUIDData struct {
	GUID string `json:"guid"`
}

type Metadata struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

type Link struct {
	Href   string `json:"href"`
	Method string `json:"method,omitempty"` // Omitted if empty, as not all links have a method
}
