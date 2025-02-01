    package example

    default allow = false

    allow {
        input.role == role
        role_permissions := roles[input.role].permissions
        permission := input.permission
        permission == role_permissions[_]
    }

    # Deny access if no matching permission is found
    deny_api_key {
        not api_key_roles[input.api_key]
    }

    # Check if the API Key is valid and associated with a role
    api_key_to_role(api_key, role) {
      role = api_key_roles[api_key]
    }

    api_key_roles = {
        "valid-api-key": "viewer",  # API key for the viewer role
        "admin-api-key": "admin"    # API key for the admin role
    }