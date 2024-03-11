package lifecycle

type GenericApp struct {
	Resources []struct {
		Lifecycle struct {
			Type string `json:"type"`
		} `json:"lifecycle"`
	} `json:"resources"`
}
