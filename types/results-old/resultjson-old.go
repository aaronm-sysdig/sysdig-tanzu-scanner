package ResultsJSONOld

type ScanResult struct {
	Metadata        Metadata        `json:"metadata"`
	Vulnerabilities Vulnerabilities `json:"vulnerabilities"`
	Packages        Packages        `json:"packages"`
	Policies        Policy          `json:"policies"`
	Info            Info            `json:"info"`
}

type Metadata struct {
	Type       string `json:"type"`
	ImageID    string `json:"imageID"`
	Digest     string `json:"digest"`
	BaseOS     string `json:"baseOS"`
	PullString string `json:"pullString"`
}

type Vulnerabilities struct {
	Total      int          `json:"total"`
	Fixable    int          `json:"fixable"`
	BySeverity []BySeverity `json:"bySeverity"`
	List       []VulnList   `json:"list"`
}

type BySeverity struct {
	Severity Severity `json:"severity"`
	Total    int      `json:"total"`
	Fixable  int      `json:"fixable"`
}

type Severity struct {
	Value      int    `json:"value"`
	Label      string `json:"label"`
	SourceName string `json:"sourceName,omitempty"`
	SourceUrl  string `json:"sourceUrl,omitempty"`
}

type VulnList struct {
	Name             string      `json:"name"`
	Severity         Severity    `json:"severity"`
	OriginalSeverity interface{} `json:"originalSeverity,omitempty"`
	CvssScore        CvssScore   `json:"cvssScore"`
	DisclosureDate   string      `json:"disclosureDate"`
	SolutionDate     string      `json:"solutionDate"`
	Exploitable      bool        `json:"exploitable"`
	Exploit          *Exploit    `json:"exploit,omitempty"` // Optional field
	AffectedPackages []string    `json:"affectedPackages"`
}

type CvssScore struct {
	Value      CvssValue `json:"value"`
	SourceName string    `json:"sourceName"`
	SourceUrl  string    `json:"sourceUrl"`
}

type CvssValue struct {
	Version string  `json:"version"`
	Score   float64 `json:"score"`
	Vector  string  `json:"vector"`
}

type Exploit struct {
	PublicationDate string   `json:"publicationDate"`
	Links           []string `json:"links"`
}

type Packages struct {
	Total int       `json:"total"`
	List  []PkgList `json:"list"`
}

type PkgList struct {
	Type            string       `json:"type"`
	Name            string       `json:"name"`
	Version         string       `json:"version"`
	SuggestedFix    string       `json:"suggestedFix"`
	PackagePath     string       `json:"packagePath"`
	VulnsBySeverity []BySeverity `json:"vulnsBySeverity"`
	Vulnerabilities []VulnList   `json:"vulnerabilities"`
	ExploitCount    int          `json:"exploitCount"`
}

type Policy struct {
	Total  int         `json:"total"`
	List   interface{} `json:"list,omitempty"`
	Status string      `json:"status"`
}

type Info struct {
	OutputJSONPath string `json:"outputJSONPath"`
	LogPath        string `json:"logPath"`
}
