if (!process.env.JIRA_HOSTNAME) {
  throw new Error("JIRA_HOSTNAME environment variable not set");
}
if (!process.env.JIRA_PROJECT) {
  throw new Error("JIRA_PROJECT environment variable not set");
}
if (!process.env.JIRA_API_TOKEN) {
  throw new Error("JIRA_API_TOKEN environment variable not set");
}

const JIRA_HOSTNAME = process.env.JIRA_HOSTNAME;
const JIRA_PROJECT = process.env.JIRA_PROJECT;

const UUID_FIELD_NAME = "UUID";
const EVENT_HAPPENED_FIELD = "Event happened";

const AUTH_TOKEN =
  "ZXJpay5nb2xkbWFuQGh1bnRlcnMuYWk6cmFiNHFUTm0wb1FUNjBhcnNjcFVCMDAy";

async function makeJiraRequest(
  url: string,
  body: any,
  method: string = "POST"
) {
  const res = await fetch(`https://${JIRA_HOSTNAME}/rest/api/3/${url}`, {
    body: JSON.stringify(body),
    method,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Basic ${AUTH_TOKEN}`,
      Accept: "application/json",
    },
  });
  if (!res.ok) {
    throw new Error(
      `Error making Jira request; ${res.status}: ${res.statusText}`
    );
  }

  return res.json();
}

interface JiraIssue {
  id: string;
  fields: { [k: string]: any };
}
type JiraNameMap = { [fieldId: string]: string };

async function fetchAndSetBasicProperties(
  issue: JiraIssue,
  names: JiraNameMap
) {}

export function GetFieldID(
  names: JiraNameMap,
  fieldName: string
): string | undefined {
  return Object.keys(names).find((k) => names[k] === fieldName);
}

export async function getTicketsToEnrich(
  statusField: string,
  hasEnrichedField: string
) {
  const unsetTicketsBasic: {
    issues: JiraIssue[];
    names: JiraNameMap;
  } = await makeJiraRequest("search", {
    jql: `project = "${JIRA_PROJECT}" AND "${UUID_FIELD_NAME}" IS NOT EMPTY AND "${statusField}" = "completed" AND ${hasEnrichedField} IS EMPTY`,
    expand: ["names"],
  });
  return unsetTicketsBasic;
}

export async function getUnsetTicketsInProject(leadStatusField: string) {
  const unsetTicketsBasic: {
    issues: JiraIssue[];
    names: JiraNameMap;
  } = await makeJiraRequest("search", {
    jql: `project = "${JIRA_PROJECT}" AND "${UUID_FIELD_NAME}" IS NOT EMPTY AND ("${leadStatusField}" IS EMPTY OR "${leadStatusField}" ~ "in progress")`,
    expand: ["names"],
  });
  return unsetTicketsBasic;
}

export async function setIssueFields(
  data: Array<{
    issueID: number;
    fields: { [fieldId: string]: any };
  }>
) {
  console.log(`Setting issue fields for ${JSON.stringify(data, null, 2)}`);
  await Promise.all(
    data.map(async (props) => {
      return makeJiraRequest(
        `issue/${props.issueID}`,
        {
          fields: props.fields,
        },
        "PUT"
      );
    })
  );
}
