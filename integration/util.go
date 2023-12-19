package integration

// concatSlice is a generic function that concatenates multiple slices of the
// same type
func concatSlice[T any](slices ...[]T) []T {
	var result []T
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}
