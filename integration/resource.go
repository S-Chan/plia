package integration

type Result struct {
	Resource  Resource `json:"resource"`
	Rule      string   `json:"rule"`
	Compliant bool     `json:"compliant"`
	Reason    string   `json:"reason"`
}

type Resource struct {
	Type string `json:"type"`
	Name string `json:"name"`
}
