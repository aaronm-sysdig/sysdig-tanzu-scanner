package oci

type OCIConfigJSON struct {
	Created      string `json:"created"`
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       struct {
		Env []string `json:"Env"`
		Cmd []string `json:"Cmd"`
	} `json:"config"`
	Rootfs struct {
		Type    string   `json:"type"`
		DiffIds []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type ManifestJSON struct {
	SchemaVersion int `json:"schemaVersion"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"layers"`
}

type IndexJSON struct {
	SchemaVersion int `json:"schemaVersion"`
	Manifests     []struct {
		MediaType   string `json:"mediaType"`
		Digest      string `json:"digest"`
		Size        int64  `json:"size"`
		Annotations struct {
			OrgOpencontainersImageRefName string `json:"org.opencontainers.image.ref.name"`
		} `json:"annotations"`
	} `json:"manifests"`
}
