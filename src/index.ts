import { HuntersAPI } from "./huntersApi";
import {
  GetFieldID,
  getTicketsToEnrich,
  getUnsetTicketsInProject,
  setIssueFields,
} from "./jiraApi";

/*
Detection Tool: Hunters
Other Detection tool: data source
Event happened : Actual event happen time as per data source or Hunters hunt.
Event Detected: Time at which Hunters alert/lead/story was created.
Severity : Use this only for High and criticals, and set to P2. For everything else, its P4 on my end.

Configuration Item: hostname
Affected user: username
IOC-Hash - SHA256 value if available (EDR, Mimecast, etc) - should have comma separated values in case more than 1
IOC-Domain/URL - should have comma separated values in case more than 1
IOC-IPAddress - should have comma separated values in case more than 1
*/

const BASIC_FIELDS = {
  DETECTION_TOOL: "Detection Tool",
  OTHER_DETECTION_TOOL: "Other Detection tool",
  EVENT_HAPPENED: "Event happened",
  EVENT_DETECTED: "Event Detected",
  SEVERITY: "Severity",
};

const ENRICHMENT_FIELDS = {
  CONFIGURATION_ITEM: "Configuration Item",
  AFFECTED_USER: "Affected user",
  IOC_HASH: "IOC-Hash",
  IOC_DOMAIN: "IOC-Domain",
  IOC_URL: "IOC-URL",
  IOC_IP: "IOC-IPAddress",
};

const LEAD_STATUS_FIELD = "Lead status";
const HAS_ENRICHED_FIELD = "Has enriched";

const huntersApi = new HuntersAPI();

async function RunBasic() {
  console.log("Fetching basic unset Jira tickets");
  const jiraTicketsBasic = await getUnsetTicketsInProject(LEAD_STATUS_FIELD);

  if (!jiraTicketsBasic.issues || jiraTicketsBasic.issues.length === 0) {
    return;
  }

  const uuidFieldId = GetFieldID(jiraTicketsBasic.names, "UUID");
  if (!uuidFieldId) {
    throw new Error("Could not find UUID field ID");
  }
  const uuidList: Array<[string, string]> = jiraTicketsBasic.issues.map(
    (issue) => [issue.id, issue.fields[uuidFieldId] as string]
  );
  console.log(`Got back basic UUIDs ${JSON.stringify(uuidList)}`);

  const JiraBasicFieldMapping: { [k: string]: string } = {};
  Object.values(BASIC_FIELDS).forEach((field) => {
    const fieldId = GetFieldID(jiraTicketsBasic.names, field);
    if (!fieldId) {
      throw new Error(`Could not find Jira field ${fieldId}`);
    }
    JiraBasicFieldMapping[field] = fieldId;
  });

  if (uuidList.length === 0) {
    console.log("No uuids to process");
  }
  const huntersUUids = uuidList.map((uuidTuple) => uuidTuple[1]);
  console.log(
    `Fetching Hunters UUIDs for basic fields: ${JSON.stringify(huntersUUids)}`
  );
  const huntersLeads = await huntersApi.fetchUuids(huntersUUids);
  console.log(JSON.stringify(huntersLeads));

  const data = huntersLeads.map((lead) => {
    const matchingJiraId = uuidList.find((tuple) => tuple[1] === lead.uuid);
    if (!matchingJiraId) {
      throw new Error(`Could not find ${lead.uuid} in Jira list`);
    }
    return {
      issueID: parseInt(matchingJiraId[0], 10),
      fields: {
        [JiraBasicFieldMapping[BASIC_FIELDS.DETECTION_TOOL]]: "Hunters",
        [JiraBasicFieldMapping[BASIC_FIELDS.OTHER_DETECTION_TOOL]]: lead.source,
        [JiraBasicFieldMapping[BASIC_FIELDS.EVENT_HAPPENED]]: lead.event_time,
        [JiraBasicFieldMapping[BASIC_FIELDS.EVENT_DETECTED]]:
          lead.detection_time,
        [JiraBasicFieldMapping[BASIC_FIELDS.SEVERITY]]:
          lead.risk === "high" || lead.risk === "critical" ? "P2" : "P4",
        [LEAD_STATUS_FIELD]: lead.status,
      },
    };
  });

  await setIssueFields(data);
}

async function RunEnrichment() {
  //https://api.us.hunters.ai/v1/mega-entities/{lead_uuid}

  console.log("Fetching enrichment unset Jira tickets");
  const jiraTickets = await getTicketsToEnrich(
    LEAD_STATUS_FIELD,
    HAS_ENRICHED_FIELD
  );

  if (!jiraTickets.issues || jiraTickets.issues.length === 0) {
    return;
  }

  const uuidFieldId = GetFieldID(jiraTickets.names, "UUID");
  if (!uuidFieldId) {
    throw new Error("Could not find UUID field ID");
  }
  const uuidList: Array<[string, string]> = jiraTickets.issues.map((issue) => [
    issue.id,
    issue.fields[uuidFieldId] as string,
  ]);
  console.log(`Got back enrichment UUIDs ${JSON.stringify(uuidList)}`);

  const JiraBasicFieldMapping: { [k: string]: string } = {};
  Object.values(BASIC_FIELDS).forEach((field) => {
    const fieldId = GetFieldID(jiraTickets.names, field);
    if (!fieldId) {
      throw new Error(`Could not find Jira field ${fieldId}`);
    }
    JiraBasicFieldMapping[field] = fieldId;
  });
}

async function main() {
  await RunBasic();
  await RunEnrichment();
}

main().catch((e) => console.error(e));
