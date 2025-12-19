# Development Process Journal

## Step 1: Requirements and Scoping
- Read through the project requirements
- Scoped resources needed for the project

## Step 2: Initialize Git Project
- Initialized git repository with an easy-to-read structure
- Created organized folder structure for better maintainability
- Enabled version control for the project

## Step 3: Initialize Basic Flask Server
- Set up Flask server to handle GET requests
- Created endpoint: `/urlinfo/1/{hostname_and_port}/{original_path_and_query_string}`
- Implemented validation functions:
  - `is_valid_scheme()` - validates HTTP/HTTPS scheme
  - `is_valid_hostname()` - validates hostname exists
  - `is_valid_port()` - validates port range (1-65535)
  - `validate_url_stages()` - orchestrates validation in stages
