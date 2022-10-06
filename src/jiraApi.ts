if (!process.env.JIRA_HOSTNAME) {
  throw new Error("JIRA_HOSTNAME environment variable not set");
}
if (!process.env.JIRA_PROJECT) {
  throw new Error("JIRA_PROJECT environment variable not set");
}
if (!process.env.JIRA_API_TOKEN) {
  throw new Error("JIRA_API_TOKEN environment variable not set");
}
if (!process.env.JIRA_API_EMAIL) {
  throw new Error("JIRA_API_EMAIL environment variable not set");
}

const JIRA_HOSTNAME = process.env.JIRA_HOSTNAME;
const JIRA_PROJECT = process.env.JIRA_PROJECT;
const JIRA_AUTH_TOKEN = Buffer.from(
  `${process.env.JIRA_API_EMAIL}:${process.env.JIRA_API_TOKEN}`
).toString("base64");

async function makeJiraRequest(
  relativeUrl: string,
  body: any,
  method: string = "POST"
) {
  const url = `https://${JIRA_HOSTNAME}/rest/api/3/${relativeUrl}`;

  console.log(`Making Jira request to ${url}`);
  const res = await fetch(url, {
    body: JSON.stringify(body),
    method,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Basic ${JIRA_AUTH_TOKEN}`,
      Accept: "application/json",
    },
  });
  if (!res.ok) {
    console.error(
      `Error making Jira request; ${res.status}: ${res.statusText}`
    );
    const body = await res.json();
    throw new Error(JSON.stringify(body));
  }

  try {
    if (method !== "PUT") {
      const jsonRes = await res.json();
      return jsonRes;
    }
    return {};
  } catch (e) {
    console.error("Could not translate Jira response into JSON");
    console.log(await res.text());
    return {};
  }
}

export interface JiraIssue {
  id: string;
  fields: { [k: string]: any };
}
export type JiraNameMap = { [fieldId: string]: string };
export interface JiraTicketResponse {
  issues: JiraIssue[];
  names: JiraNameMap;
}

export function GetFieldID(
  names: JiraNameMap,
  fieldName: string
): string | undefined {
  return Object.keys(names).find(
    (k) => names[k].toLocaleLowerCase() === fieldName.toLocaleLowerCase()
  );
}

export async function getTicketsToEnrich(
  statusField: string,
  hasEnrichedField: string,
  uuidField: string
): Promise<JiraTicketResponse> {
  const unsetTicketsBasic: {
    issues: JiraIssue[];
    names: JiraNameMap;
  } = await makeJiraRequest("search", {
    jql: `project = "${JIRA_PROJECT}" AND issuetype="Security Incident Record" AND "${uuidField}" IS NOT EMPTY AND "${statusField}" ~ "completed" AND "${hasEnrichedField}" IS EMPTY`,
    expand: ["names"],
  });
  return unsetTicketsBasic;
}

export async function getTicketsWithoutUUID(
  uuidField: string
): Promise<JiraTicketResponse> {
  const jql = `project = "${JIRA_PROJECT}" AND issuetype="Security Incident Record" AND "${uuidField}" IS EMPTY`;
  console.log(jql);
  const unsetTicketsBasic: {
    issues: JiraIssue[];
    names: JiraNameMap;
  } = await makeJiraRequest("search", {
    jql,
    expand: ["names"],
  });
  return unsetTicketsBasic;
}

export async function getUnsetTicketsInProject(
  leadStatusField: string,
  uuidField: string
): Promise<JiraTicketResponse> {
  const jql = `project = "${JIRA_PROJECT}" AND issuetype="Security Incident Record" AND "${uuidField}" IS NOT EMPTY AND ("${leadStatusField}" IS EMPTY OR "${leadStatusField}" ~ "in progress")`;
  console.log(jql);
  const unsetTicketsBasic: {
    issues: JiraIssue[];
    names: JiraNameMap;
  } = await makeJiraRequest("search", {
    jql,
    expand: ["names"],
  });
  return unsetTicketsBasic;
}

interface JiraDescriptionContent {
  type: string;
  text?: string;
  content?: JiraDescriptionContent[];
}
export function flattenDescriptionText(
  description: JiraDescriptionContent | undefined | string
): string[] {
  if (!description) {
    return [];
  }
  if (typeof description === "string") {
    return [description];
  }

  const continuation = description.content
    ? description.content.map((c) => flattenDescriptionText(c)).flat()
    : [];

  if (description.text) {
    return [description.text, ...continuation];
  }
  return continuation;
}

export async function getIssueMetaFields(issueId: number) {
  const res = await makeJiraRequest(
    `issue/${issueId}/editmeta`,
    undefined,
    "GET"
  );
  console.log(JSON.stringify(res, null, 2));
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
      let res;
      try {
        res = await makeJiraRequest(
          `issue/${props.issueID}`,
          {
            fields: props.fields,
          },
          "PUT"
        );
      } catch (e) {
        console.error(
          `Error setting field for ${props.issueID} ${JSON.stringify(
            props.fields,
            null,
            2
          )}`
        );
        console.error(e);
      }
    })
  );
  console.log("Done setting issue fields");
}
