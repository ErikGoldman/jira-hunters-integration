import { HuntersAPI } from "./huntersApi";
import {
  GetFieldID,
  getUnsetBasicTicketsInProject,
  setIssueFields,
} from "./jiraApi";

/*
Configuration Item: hostname
Affected user: username
Detection Tool: Hunters
Other Detection tool: data source
Event happened : Actual event happen time as per data source or Hunters hunt.
Event Detected: Time at which Hunters alert/lead/story was created.
Severity : Use this only for High and criticals, and set to P2. For everything else, its P4 on my end.
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

async function main() {
  const huntersApi = new HuntersAPI();

  console.log("Fetching basic unset Jira tickets");
  const jiraTicketsBasic = await getUnsetBasicTicketsInProject();

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

  if (uuidList.length > 0) {
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
          [JiraBasicFieldMapping[BASIC_FIELDS.OTHER_DETECTION_TOOL]]:
            lead.source,
          [JiraBasicFieldMapping[BASIC_FIELDS.EVENT_HAPPENED]]: lead.event_time,
          [JiraBasicFieldMapping[BASIC_FIELDS.EVENT_DETECTED]]:
            lead.detection_time,
          [JiraBasicFieldMapping[BASIC_FIELDS.SEVERITY]]:
            lead.risk === "high" || lead.risk === "critical" ? "P2" : "P4",
        },
      };
    });

    await setIssueFields(data);
  }
}

main().catch((e) => console.error(e));
