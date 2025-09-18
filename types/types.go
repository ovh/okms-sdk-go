package types

type ListSecretV2ResponseWithPagination struct {
	ListSecretV2Response ListSecretV2Response
	PageCursorNext       string
}

type ListSecretVersionV2ResponseWithPagination struct {
	ListSecretVersionV2Response ListSecretVersionV2Response
	PageCursorNext              string
}
