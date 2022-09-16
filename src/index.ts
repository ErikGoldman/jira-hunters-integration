import { HuntersAPI, HuntersME, KindMapping } from "./huntersApi";
import {
  GetFieldID,
  getTicketsToEnrich,
  getUnsetTicketsInProject,
  JiraTicketResponse,
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

const FIELDS = {
  DETECTION_TOOL: "Detection Tool",
  OTHER_DETECTION_TOOL: "Other Detection tool",
  EVENT_HAPPENED: "Event happened",
  EVENT_DETECTED: "Event Detected",
  SEVERITY: "Severity",
  INVESTIGATION_STATE_FIELD: "Investigation state",
  HAS_ENRICHED_FIELD: "Has enriched",

  CONFIGURATION_ITEM: "Configuration Item",
  AFFECTED_USER: "Affected user",
  IOC_HASH: "IOC-Hash",
  IOC_DOMAIN: "IOC-Domain",
  IOC_URL: "IOC-URL",
  IOC_IP: "IOC-IPAddress",
};

const huntersApi = new HuntersAPI();

function GetUUIDsToProcess(
  jiraTickets: JiraTicketResponse
): [Array<[string, string]>, { [fieldName: string]: string }] {
  if (!jiraTickets.issues || jiraTickets.issues.length === 0) {
    return [[], {}];
  }

  const uuidFieldId = GetFieldID(jiraTickets.names, "UUID");
  if (!uuidFieldId) {
    throw new Error("Could not find UUID field ID");
  }
  const uuidList: Array<[string, string]> = jiraTickets.issues.map((issue) => [
    issue.id,
    issue.fields[uuidFieldId] as string,
  ]);
  console.log(`Got UUIDs ${JSON.stringify(uuidList)}`);

  if (uuidList.length === 0) {
    return [[], {}];
  }

  const JiraBasicFieldMapping: { [k: string]: string } = {};
  Object.values(FIELDS).forEach((field) => {
    const fieldId = GetFieldID(jiraTickets.names, field);
    if (!fieldId) {
      throw new Error(`Could not find Jira field ${field}`);
    }
    JiraBasicFieldMapping[field] = fieldId;
  });

  if (uuidList.length === 0) {
    console.log("No uuids to process");
  }
  return [uuidList, JiraBasicFieldMapping];
}

async function RunBasic() {
  console.log("Fetching basic unset Jira tickets");
  const jiraTicketsBasic = await getUnsetTicketsInProject(
    FIELDS.INVESTIGATION_STATE_FIELD
  );

  const [uuidList, JiraBasicFieldMapping] = GetUUIDsToProcess(jiraTicketsBasic);
  const huntersUUids = uuidList.map((uuidTuple) => uuidTuple[1]);

  if (huntersUUids.length === 0) {
    console.log("No basic UUIDs");
    return;
  }

  console.log(
    `Fetching Hunters UUIDs for basic fields: ${JSON.stringify(huntersUUids)}`
  );
  const huntersLeads = await huntersApi.fetchFromUuids(huntersUUids);

  const data = huntersLeads.map((lead) => {
    const matchingJiraId = uuidList.find((tuple) => tuple[1] === lead.uuid);
    if (!matchingJiraId) {
      throw new Error(`Could not find ${lead.uuid} in Jira list`);
    }
    return {
      issueID: parseInt(matchingJiraId[0], 10),
      fields: {
        [JiraBasicFieldMapping[FIELDS.DETECTION_TOOL]]: "Hunters",
        [JiraBasicFieldMapping[FIELDS.OTHER_DETECTION_TOOL]]: lead.source,
        [JiraBasicFieldMapping[FIELDS.EVENT_HAPPENED]]: lead.event_time,
        [JiraBasicFieldMapping[FIELDS.EVENT_DETECTED]]: lead.detection_time,
        [JiraBasicFieldMapping[FIELDS.SEVERITY]]:
          lead.risk === "high" || lead.risk === "critical" ? "P2" : "P4",
        [JiraBasicFieldMapping[FIELDS.INVESTIGATION_STATE_FIELD]]:
          lead.investigation_state,
      },
    };
  });

  await setIssueFields(data);
}

function getMEValueOrEmpty(
  meResponse: HuntersME[],
  highLevelKind: keyof typeof KindMapping
) {
  const matchingAttributes = meResponse
    .map((me) =>
      Object.values(me.attributes).map((attr) =>
        attr && KindMapping[highLevelKind].find((k) => k === attr.kind)
          ? me.attributes[attr.name].value
          : undefined
      )
    )
    .flat()
    .filter((x) => x) as string[];
  if (matchingAttributes.length === 0) {
    return "";
  }
  return matchingAttributes.join(",");
}

async function RunEnrichment() {
  console.log("Fetching enrichment unset Jira tickets");
  const jiraTickets = await getTicketsToEnrich(
    FIELDS.INVESTIGATION_STATE_FIELD,
    FIELDS.HAS_ENRICHED_FIELD
  );

  const [uuidList, JiraFieldMapping] = GetUUIDsToProcess(jiraTickets);
  const huntersUUids = uuidList.map((uuidTuple) => uuidTuple[1]);

  if (huntersUUids.length === 0) {
    console.log("No enrichment UUIDs");
    return;
  }

  console.log(
    `Fetching Hunters megaentities for enrichment fields: ${JSON.stringify(
      huntersUUids
    )}`
  );
  const huntersMEs = await huntersApi.fetchMegaentities(huntersUUids);

  const data = huntersMEs.map((me) => {
    const matchingJiraId = uuidList.find(
      (tuple) => tuple[1] === me[0].lead_uuid
    );
    if (!matchingJiraId) {
      throw new Error(`Could not find ${me[0].lead_uuid} in Jira list`);
    }

    const fields: { [k: string]: string } = {};
    if (me && me.length !== 0) {
      console.log(
        `Got ME attributes for ${me[0].lead_uuid}: ${JSON.stringify(
          me.map((m) => m.attributes),
          null,
          2
        )}`
      );
      fields[JiraFieldMapping[FIELDS.CONFIGURATION_ITEM]] = getMEValueOrEmpty(
        me,
        "hostname"
      );
      fields[JiraFieldMapping[FIELDS.AFFECTED_USER]] = getMEValueOrEmpty(
        me,
        "username"
      );
      fields[JiraFieldMapping[FIELDS.IOC_DOMAIN]] = getMEValueOrEmpty(
        me,
        "domain"
      );
      fields[JiraFieldMapping[FIELDS.IOC_HASH]] = getMEValueOrEmpty(me, "hash");
      fields[JiraFieldMapping[FIELDS.IOC_URL]] = getMEValueOrEmpty(me, "url");
      fields[JiraFieldMapping[FIELDS.IOC_IP]] = getMEValueOrEmpty(me, "ip");
    }
    fields[JiraFieldMapping[FIELDS.HAS_ENRICHED_FIELD]] = "true";

    return {
      issueID: parseInt(matchingJiraId[0], 10),
      fields,
    };
  });

  await setIssueFields(data);
}

// just for testing
async function GetInterestingUUIDs() {
  const leads = await huntersApi.fetchAllUUIDs();
  const MEs = await huntersApi.fetchMegaentities(
    leads.slice(5, 35).map((lead) => lead.uuid)
  );
  return MEs.filter((me) =>
    me.find((e) => Object.values(e.attributes).find((a) => a.value))
  )
    .filter((x) => x)
    .map((m) => m[0].lead_uuid);
}

async function main() {
  // console.log(JSON.stringify(await GetInterestingUUIDs(), null, 2));

  await RunBasic();
  await RunEnrichment();
}

main().catch((e) => console.error(e));
