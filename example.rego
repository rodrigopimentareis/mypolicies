package example

import rego.v1

# Default deny
default allow := false

# Define roles and their permissions
roles := {
	"admin": {"permissions": ["read", "write", "delete"]},
	"viewer": {"permissions": ["read"]},
}

# Main allow rule
allow if {
	# First verify API key and get role
	role := api_key_roles[input.api_key]

	# Check if the requested permission exists for the role
	role_permissions := roles[role].permissions
	permission := input.permission
	permission == role_permissions[_]
}

# API key validation
deny_api_key if {
	not api_key_roles[input.api_key]
}

# Helper function to get role from API key
api_key_to_role(api_key) := role if {
	role := api_key_roles[api_key]
}

# API key to role mapping
api_key_roles := {
	"valid-api-key": "viewer", # API key for the viewer role
	"admin-api-key": "admin", # API key for the admin role
}
