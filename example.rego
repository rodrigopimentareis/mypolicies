package example

import rego.v1

# Default deny
default allow := false

default allow_api_key := false

# Define roles and their permissions
roles := {
	"admin": {"permissions": ["read_users", "write_users"]},
	"viewer": {"permissions": ["read"]},
}

# API key validation
allow_api_key if {
	api_key_roles[input.api_key]
}

# Main allow rule (only runs if API key is valid)
allow if {
	# First verify API key and get role
	role := api_key_roles[input.api_key]

	# Check if the requested permission exists for the role
	role_permissions := roles[role].permissions
	permission := input.permission
	permission == role_permissions[_]
}

# API key to role mapping
api_key_roles := {
	"valid-api-key": "viewer", # API key for the viewer role
	"admin-api-key": "admin", # API key for the admin role
}
