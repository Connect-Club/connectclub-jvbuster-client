package jvbuster

type HeaderTemplateData struct {
	SessionId int64
	SessionVersion int64
	ConferenceId string
	Ufrag string
	Pwd string
	MediaIds []string
	Fingerprints []Fingerprpint
}

type ApplicationChannelTemplateData struct {
	MediaId string
	Candidates []Candidate
}

type MainChannelTemplateData struct {
	MediaId string
	Direction string
	Bandwidth int
	Sources []int64
	Candidates []Candidate
}

type ParticipantChannelTemplateData struct {
	Id string
	MediaId string
	Endpoint string
	SsrcGroups []SsrcGroup
	Ssrcs []int64
	Candidates []Candidate
}
