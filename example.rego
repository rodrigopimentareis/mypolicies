package example

import rego.v1

# Define roles and their permissions
roles := {
	"admin": {"permissions": ["read_users", "write_users", "delete_users"]},
	"viewer": {"permissions": ["read_users"]}
}

# API key to role mapping
api_key_roles := {
	"valid-api-key": "viewer",
	"admin-api-key": "admin"
}

# Check if API key exists
valid_api_key := api_key_roles[input.api_key]

# Authentication Response: Check if API key exists
auth_response := {
	"valid": valid_api_key != null,
	"role": valid_api_key
}

# Authorization Response: Check if the role has permission
allow := permission == roles[valid_api_key].permissions[_] if {
	permission := input.permission
	valid_api_key != null
}

authz_response := {
	"allow": allow,
	"role": valid_api_key
}
