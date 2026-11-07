# Bug Bounty Testing Rules

BugRecon must avoid reporting invalid vulnerabilities.

Do NOT report:

- open redirects without impact
- banner disclosure
- missing headers
- theoretical vulnerabilities
- self XSS
- clickjacking without sensitive actions

Testing must NOT:

- cause DoS
- send excessive traffic
- spam users
- perform social engineering

Always verify:

- real security impact
- exploitability
- reproducibility