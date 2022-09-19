# Jira <-> Hunters integration

This integration pulls the Hunters UUID from the body of a Jira ticket and immediately populates
a few basic fields from the lead.

After the investigation is complete, it will pull in drilldown data and connected entities.

## Setup

To run this, you must set the following environment variables:

`JIRA_HOSTNAME`: where your Jira is hosted (xyz.atlassian.net for cloud Jira)
`JIRA_API_TOKEN`: [your Jira API token](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)
`JIRA_API_EMAIL`: your Jira username (abc@yourcompany.com)
`JIRA_PROJECT`: the name of the Jira project to watch ("Hunters Project")
`HUNTERS_API_CLIENT_ID`: [your Hunters API client ID](https://api-docs.hunters.ai/docs/api-ref/ZG9jOjExMDcyMQ-api-token-management)
`HUNTERS_API_SECRET_KEY`: [your Hunters API secret key](https://api-docs.hunters.ai/docs/api-ref/ZG9jOjExMDcyMQ-api-token-management)

Additionally, this looks for the following text fields in your Jira project:

"Detection Tool": will always set to Hunters
"Other Detection tool": data source
"Event happened": timestamp from the original data source
"Event Detected": timestamp when the lead was created
"Severity": high and critical -> P2, everything else becomes P4
"Investigation state": ignore/in-progress/complete
"Has enriched": used for internal bookkeeping
"UUID": the UUID of the lead

"Configuration Item": hostname
"Affected user": username
"IOC-Hash": any relevant hashes
"IOC-Domain": any relevant domains
"IOC-URL": any relevant URLs
"IOC-IPAddress": any relevant IPs

If you want to change the name of any of these fields in your project, you should modify the definitions at the top of the file `src/index.ts`
