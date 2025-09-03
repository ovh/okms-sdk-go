package utils

// PtrTo returns a pointer to a copy of the given argument.
func PtrTo[T any](v T) *T { return &v }

// StringPtr returns a pointer to the passed string value.
// It's useful in places where you want to init a new string ptr, without the burden
// of having to create it in a variable then getting the pointer to that variable.
func StringPtr(v string) *string { return PtrTo(v) }
