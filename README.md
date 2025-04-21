# FastAPI CVE Dashboard – Detailed API Documentation & Test Cases

## 1. Introduction
The FastAPI CVE Dashboard is a powerful application built with FastAPI that allows users to view, search, and analyze Common Vulnerabilities and Exposures (CVE) data. It fetches CVEs from the National Vulnerability Database (NVD) API, stores them in a local SQLite database using SQLAlchemy, and presents the data through a REST API and an interactive web interface.

Key features include:
- Data Deduplication
- Periodic Data Synchronization
- Rich API Endpoints
- Filterable Web Interface

## 2. Data Model
The application uses two primary data models:
- **CVE**: Stores vulnerability information such as ID, description, CVSS v2/v3 scores, vector strings, and timestamps.
- **CPE**: Represents the Common Platform Enumerations associated with each CVE, helping identify the affected systems.

## 3. API Endpoints

### `/cves/list`
- **Method**: GET
- **Description**: Returns a paginated list of CVEs with optional sorting.
- **Parameters**:
  - `skip` (int): Offset for pagination
  - `limit` (int): Number of results to return
  - `sort_by` (str): Field to sort by (`published_date`, `last_modified_date`)
  - `sort_order` (str): Sort order (`asc`, `desc`)
- **Response**: JSON object with `records` and `total`

### `/cves/{cve_id}/json`
- **Method**: GET
- **Description**: Returns detailed information about a specific CVE in JSON format.
- **Parameters**:
  - `cve_id` (str): The unique CVE identifier
- **Response**: Full CVE details, including metrics and associated CPEs

### `/cve-detail/{cve_id}`
- **Method**: GET (UI)
- **Description**: Renders a detailed HTML page for the selected CVE.
- **Parameters**:
  - `cve_id` (str): The CVE identifier
- **Response**: Jinja2-rendered HTML page

### `/cves/year/{year}`
- **Method**: GET
- **Description**: Fetches all CVEs published in a given year.
- **Parameters**:
  - `year` (int): The year to query
- **Response**: JSON list of CVEs

### `/cves/score`
- **Method**: GET
- **Description**: Returns CVEs filtered by CVSS score range.
- **Parameters**:
  - `min_score` (float): Minimum score
  - `max_score` (float): Maximum score
  - `skip`, `limit` for pagination
- **Response**: Paginated JSON of filtered CVEs

### `/ui`
- **Method**: GET (UI)
- **Description**: Main HTML dashboard with search, sort, and pagination.
- **Response**: Rendered HTML page

## 4. Core Functionalities

### Data Deduplication (`deduplicate.py`)
To avoid storing duplicate CVEs, the system checks if a CVE ID already exists in the database before inserting:

This process ensures that only unique CVEs are preserved.

### Data Synchronization (`fetch_cve_data.py`)
The system periodically syncs with the NVD API to retrieve new CVE data using:

This process can be run in the background or scheduled using tools like APScheduler.

### API Routes (`main.py`)
All major functionalities are exposed through FastAPI routes. Example definition:

FastAPI automatically generates documentation at `/docs` and `/redoc`.

### Web Interface (`templates/index.html`)
A dynamic web interface is built using Jinja2 templates. It supports filtering by CVSS score, dates, and keywords:

This allows users to interactively search and analyze vulnerability data.

## 5. Testing

### 5.1 Unit Test Cases
- Validate database connection and table creation
- Confirm correct HTTP status codes for each endpoint
- Test pagination and sorting mechanisms
- Validate filtering by CVSS score (min and max)
- Ensure JSON and UI responses are properly structured

### 5.2 Manual Test Scenarios
- Open `/ui` and verify data loads with pagination
- Adjust result count per page and validate update
- Navigate to CVE detail by clicking on CVE ID
- Sort table columns and check order
- Verify presence of CPE and CVSS vector data
- Test invalid CVE IDs and confirm proper error messages

## 6. Conclusion
The FastAPI CVE Dashboard provides a structured and scalable platform for CVE analysis. With its API-first approach and complementary web UI, users can access, filter, and visualize vulnerability data efficiently. Its modular architecture allows for future expansion such as advanced filtering, real-time alerts, and dashboard analytics.

