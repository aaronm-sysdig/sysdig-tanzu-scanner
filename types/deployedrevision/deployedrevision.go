package deployedrevision

type DeployedRevisionsResponse struct {
	Pagination struct {
		TotalResults int `json:"total_results"`
		TotalPages   int `json:"total_pages"`
		First        struct {
			Href string `json:"href"`
		} `json:"first"`
		Last struct {
			Href string `json:"href"`
		} `json:"last"`
		Next     interface{} `json:"next"`
		Previous interface{} `json:"previous"`
	} `json:"pagination"`
	Resources []struct {
		Guid    string `json:"guid"`
		Version int64  `json:"version"`
		Droplet struct {
			Guid string `json:"guid"`
		} `json:"droplet"`
		Processes struct {
			Web struct {
				Command interface{} `json:"command"`
			} `json:"web"`
		} `json:"processes"`
		Sidecars      []interface{} `json:"sidecars"`
		Description   string        `json:"description"`
		Relationships struct {
			App struct {
				Data struct {
					Guid string `json:"guid"`
				} `json:"data"`
			} `json:"app"`
		} `json:"relationships"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Links     struct {
			Self struct {
				Href string `json:"href"`
			} `json:"self"`
			App struct {
				Href string `json:"href"`
			} `json:"app"`
			EnvironmentVariables struct {
				Href string `json:"href"`
			} `json:"environment_variables"`
		} `json:"links"`
		Metadata struct {
			Labels      map[string]interface{} `json:"labels"`
			Annotations map[string]interface{} `json:"annotations"`
		} `json:"metadata"`
		Deployable bool `json:"deployable"`
	} `json:"resources"`
}
