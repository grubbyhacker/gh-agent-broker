package sandbox

// TransportStage describes a broker-recorded smart-HTTP stage. The broker
// persists these safe, credential-free facts through its audit logger before
// authentication and admission, so rejected Git requests remain observable.
//
// This type intentionally has no registered-task, green-PR, agentd, or
// authority-worker fields. The broker's normal agent authentication remains
// the source of identity for every production Git operation.
type TransportStage struct {
	OperationID             string
	Method                  string
	Service                 string
	Repository              string
	RequestPath             string
	CredentialHeaderPresent bool
	Stage                   string
	Decision                string
	Reason                  string
	HTTPStatus              int
	AgentID                 string
}
