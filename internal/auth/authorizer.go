package auth

type Authorizer interface {
	Authorize(subj, obj, action string) error
}
