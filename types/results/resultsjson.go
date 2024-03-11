package ResultsJSON

type ScanResult struct {
	Info     Info      `json:"info"`
	Scanner  Scanner   `json:"scanner"`
	Result   Result    `json:"result"`
	Failures []Failure `json:"failures"`
}

type Info struct {
	ScanTime     string `json:"scanTime"`
	ScanDuration string `json:"scanDuration"`
}

type Scanner struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Result struct {
	Type                       string             `json:"type"`
	Metadata                   Metadata           `json:"metadata"`
	VulnTotalBySeverity        map[string]int     `json:"vulnTotalBySeverity"`
	FixableVulnTotalBySeverity map[string]int     `json:"fixableVulnTotalBySeverity"`
	ExploitsCount              int                `json:"exploitsCount"`
	Packages                   []Package          `json:"packages"`
	PolicyEvaluations          []PolicyEvaluation `json:"policyEvaluations"`
}

type Metadata struct {
	PullString   string `json:"pullString"`
	ImageId      string `json:"imageId"`
	Digest       string `json:"digest"`
	BaseOs       string `json:"baseOs"`
	Size         int    `json:"size"`
	Os           string `json:"os"`
	Architecture string `json:"architecture"`
	LayersCount  int    `json:"layersCount"`
	CreatedAt    string `json:"createdAt"`
}

type Package struct {
	Type         string          `json:"type"`
	Name         string          `json:"name"`
	Version      string          `json:"version"`
	Path         string          `json:"path"`
	SuggestedFix string          `json:"suggestedFix,omitempty"`
	Vulns        []Vulnerability `json:"vulns,omitempty"`
}

type Vulnerability struct {
	Name           string    `json:"name"`
	Severity       Severity  `json:"severity"`
	CvssScore      CvssScore `json:"cvssScore"`
	DisclosureDate string    `json:"disclosureDate"`
	SolutionDate   string    `json:"solutionDate"`
	Exploitable    bool      `json:"exploitable"`
	FixedInVersion string    `json:"fixedInVersion"`
}

type Severity struct {
	Value      string `json:"value"`
	SourceName string `json:"sourceName"`
}

type CvssScore struct {
	Value struct {
		Version string  `json:"version"`
		Score   float64 `json:"score"`
		Vector  string  `json:"vector"`
	} `json:"value"`
	SourceName string `json:"sourceName"`
}

type Reference struct {
	PkgIndex       int    `json:"pkgIndex"`
	VulnInPkgIndex int    `json:"vulnInPkgIndex"`
	Ref            string `json:"ref"`
	Description    string `json:"description"`
}

type PolicyEvaluation struct {
	Name              string   `json:"name"`
	Identifier        string   `json:"identifier"`
	Type              string   `json:"type"`
	Bundles           []Bundle `json:"bundles"`
	AcceptedRiskTotal int      `json:"acceptedRiskTotal"`
	EvaluationResult  string   `json:"evaluationResult"`
	CreatedAt         string   `json:"createdAt"`
	UpdatedAt         string   `json:"updatedAt"`
}

type Bundle struct {
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
	Type       string `json:"type"`
	Rules      []Rule `json:"rules"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

type Rule struct {
	RuleType         string      `json:"ruleType"`
	FailureType      string      `json:"failureType"`
	Description      string      `json:"description"`
	Failures         []Failure   `json:"failures"`
	EvaluationResult string      `json:"evaluationResult"`
	Predicates       []Predicate `json:"predicates"`
}

type Failure struct {
	PkgIndex       int    `json:"pkgIndex"`
	VulnInPkgIndex int    `json:"vulnInPkgIndex"`
	Ref            string `json:"ref"`
	Description    string `json:"description"`
}

type Predicate struct {
	Type  string `json:"type"`
	Extra Extra  `json:"extra"`
}

type Extra struct {
	Level string `json:"level,omitempty"`
	Age   int    `json:"age,omitempty"`
}
