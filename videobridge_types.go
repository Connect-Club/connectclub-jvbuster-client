package jvbuster

type Offer struct {
	VideobridgeId       string
	ConferenceId        string
	Ufrag               string
	Pwd                 string
	Fingerprints        []Fingerprpint
	Candidates          []Candidate
	RtcpMux             bool
	SctpConnectionId    string
	PrimaryAudioChannel PrimaryChannel
	PrimaryVideoChannel PrimaryChannel
	AudioChannels       []Channel
	VideoChannels       []Channel
	Endpoints           []Endpoint
	endpointToUuid      map[string]string
}

type Fingerprpint struct {
	Value string
	Hash  string
	Setup string
}

type Candidate struct {
	Foundation string
	Component int
	Protocol string
	Priority int
	Ip string
	Port int
	Type string
	RelAddr string
	RelPort int
	Generation string
}

type PrimaryChannel struct {
	Id string
	Direction string
	Sources []int64
}

type Channel struct {
	Id string
	Endpoint string
	Ssrcs []int64
	SsrcGroups []SsrcGroup
}

type SsrcGroup struct {
	Semantics string
	Ssrcs []int64
}

type Endpoint struct {
	Id string
	Uuid string
}