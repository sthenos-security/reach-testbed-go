package safety

import "regexp"

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]{1,253}$`)

func AllowedHostname(host string) bool {
	return hostPattern.MatchString(host)
}

func AllowedLanguageTag(tag string) bool {
	switch tag {
	case "en", "en-US", "fr", "fr-FR", "es", "es-ES":
		return true
	default:
		return false
	}
}
