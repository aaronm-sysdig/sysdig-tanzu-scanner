package currentdroplet

import (
	"time"
)

type CurrentDroplet struct {
	GUID              string            `json:"guid"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	State             string            `json:"state"`
	Error             interface{}       `json:"error"`
	Lifecycle         Lifecycle         `json:"lifecycle"`
	Checksum          Checksum          `json:"checksum"`
	Buildpacks        []Buildpack       `json:"buildpacks"`
	Stack             string            `json:"stack"`
	Image             interface{}       `json:"image"`
	ExecutionMetadata string            `json:"execution_metadata"`
	ProcessTypes      map[string]string `json:"process_types"`
	Relationships     Relationships     `json:"relationships"`
	Metadata          Metadata          `json:"metadata"`
	Links             map[string]Link   `json:"links"`
}

type Lifecycle struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data"` // Empty object, use map[string]interface{} for flexibility
}

type Checksum struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Buildpack struct {
	Name          string      `json:"name"`
	DetectOutput  interface{} `json:"detect_output"` // null or string, use interface{}
	BuildpackName string      `json:"buildpack_name"`
	Version       string      `json:"version"`
}

type Relationships struct {
	App RelationshipData `json:"app"`
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
	Href   string `json:"href"`
	Method string `json:"method,omitempty"` // Include omitempty to omit the field if it's empty
}
